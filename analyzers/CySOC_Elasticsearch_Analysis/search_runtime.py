"""Best-effort, bounded runtime policy for one Elasticsearch endpoint.

Monitoring never determines whether evidence is complete and never changes the
query, requested evidence count, returned fields, or counting threshold. Limits
only decrease during a run. A single pressure sample is reported as an observed
signal, rather than as sustained load. Elasticsearch's transport remains the
only HTTP retry implementation.
"""

from collections.abc import Mapping
from contextlib import contextmanager
import json
import random
import threading
import time


class EndpointRuntimeController:
    """Share adaptive ceilings and a concurrency gate between pattern workers."""

    MONITOR_TIMEOUT_SECONDS = 2
    MONITOR_REFRESH_SECONDS = 30
    RESPONSE_BYTES_THRESHOLD = 4 * 1024 * 1024
    MAX_BACKOFF_SECONDS = 0.75
    _STATS_FILTER = (
        "nodes.*.os.cpu.percent",
        "nodes.*.jvm.mem.heap_used_percent",
        "nodes.*.thread_pool.search*.queue",
        "nodes.*.thread_pool.search*.rejected",
    )

    def __init__(self, es, max_concurrency, max_shard_requests, max_page_size,
                 secrets=()):
        self.es = es
        # No exception messages or arbitrary server fields enter diagnostics.
        # secrets is accepted for callers sharing their normal redaction API.
        del secrets
        self._condition = threading.Condition(threading.RLock())
        self._configured = {
            "search_concurrency": max(1, int(max_concurrency)),
            "max_concurrent_shard_requests": max(1, int(max_shard_requests)),
            "page_size": max(1, int(max_page_size)),
        }
        self._limits = dict(self._configured)
        self._active = 0
        self._active_requests = 0
        self._max_active_requests = 0
        self._sampling = False
        self._monitor_disabled = False
        self._last_sample_at = None
        self._rejection_baseline = {}
        self._monitoring = {
            "status": "not_sampled", "samples": 0, "failures": 0,
            "last_error": None, "last_sample": None,
            "refresh_interval_seconds": self.MONITOR_REFRESH_SECONDS,
        }
        self._signals = []
        self._adjustments = []
        self._requests_observed = 0
        self._timeouts = 0
        self._overload_responses = 0
        self._max_response_bytes = 0
        self._latency = {"samples": 0, "last_ms": None, "max_ms": None, "mean_ms": 0.0}
        self._next_request_at = 0.0
        self._pacing = {"events": 0, "waits": 0, "total_wait_ms": 0.0}

    @property
    def concurrency(self):
        with self._condition:
            return self._limits["search_concurrency"]

    @property
    def shard_requests(self):
        with self._condition:
            return self._limits["max_concurrent_shard_requests"]

    @property
    def page_size(self):
        with self._condition:
            return self._limits["page_size"]

    def limits(self):
        with self._condition:
            return dict(self._limits)

    @contextmanager
    def permit(self):
        """Optional pattern-admission gate; use request_permit for HTTP work.

        A reduced ceiling applies to subsequent admissions. Existing work is
        allowed to finish and is never cancelled or silently omitted.
        """
        with self._condition:
            while self._active >= self._limits["search_concurrency"]:
                self._condition.wait()
            self._active += 1
        try:
            yield
        finally:
            with self._condition:
                self._active -= 1
                self._condition.notify_all()

    @contextmanager
    def request_permit(self):
        """Apply the current ceiling to every new search HTTP request.

        Already running requests finish normally when the ceiling decreases.
        Subsequent pages wait, including pages of patterns already in progress.
        Acquire this once per HTTP call, without nesting request permits.
        """
        with self._condition:
            while self._active_requests >= self._limits["search_concurrency"]:
                self._condition.wait()
            self._active_requests += 1
            self._max_active_requests = max(self._max_active_requests, self._active_requests)
        try:
            yield
        finally:
            with self._condition:
                self._active_requests -= 1
                self._condition.notify_all()

    def initialize(self):
        self.sample()
        return self.snapshot()

    @staticmethod
    def _body(response):
        body = getattr(response, "body", response)
        return body if isinstance(body, Mapping) else None

    @staticmethod
    def _number(value):
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if 0 <= value < float("inf"):
                return value
        return None

    @staticmethod
    def _counter(value):
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None

    @staticmethod
    def _status(value):
        candidates = (
            getattr(value, "status_code", None),
            getattr(getattr(value, "meta", None), "status", None),
        )
        if isinstance(value, Mapping):
            candidates += (value.get("status"),)
        for status in candidates:
            if isinstance(status, int) and not isinstance(status, bool):
                return status
        return None

    @staticmethod
    def _is_timeout(error):
        if error is None:
            return False
        # Inspect exception types, never credential-bearing exception text.
        timeout_types = {
            "TimeoutError", "ConnectionTimeout", "ReadTimeoutError",
            "ReadTimeout", "ConnectTimeout", "ConnectTimeoutError",
        }
        return any(base.__name__ in timeout_types for base in type(error).__mro__)

    def _signal(self, code):
        if code not in self._signals:
            self._signals.append(code)

    def _reduce(self, reason, *, conservative=False, page=False):
        """Called with the condition held; ceilings never increase."""
        self._signal(reason)
        previous = dict(self._limits)
        if page:
            self._limits["page_size"] = max(1, self._limits["page_size"] // 2)
        else:
            for key in ("search_concurrency", "max_concurrent_shard_requests"):
                self._limits[key] = 1 if conservative else max(1, self._limits[key] // 2)
        if previous != self._limits:
            self._adjustments.append({
                "reason": reason, "before": previous, "after": dict(self._limits),
            })
            self._condition.notify_all()

    def _parse_metrics(self, body):
        nodes = body.get("nodes") if body else None
        if not isinstance(nodes, Mapping) or not nodes:
            return None, None
        cpus, heaps, queues = [], [], []
        rejections = {}
        sampled = 0
        for node_id, node in nodes.items():
            if not isinstance(node, Mapping):
                continue
            valid = False
            os_data = node.get("os", {})
            cpu_data = os_data.get("cpu", {}) if isinstance(os_data, Mapping) else {}
            cpu = self._number(cpu_data.get("percent")) if isinstance(cpu_data, Mapping) else None
            jvm = node.get("jvm", {})
            mem = jvm.get("mem", {}) if isinstance(jvm, Mapping) else {}
            heap = self._number(mem.get("heap_used_percent")) if isinstance(mem, Mapping) else None
            cpu = cpu if cpu is not None and cpu <= 100 else None
            heap = heap if heap is not None and heap <= 100 else None
            if cpu is not None:
                cpus.append(cpu)
                valid = True
            if heap is not None:
                heaps.append(heap)
                valid = True
            pools = node.get("thread_pool", {})
            if isinstance(pools, Mapping):
                for pool_name, pool in pools.items():
                    if not str(pool_name).startswith("search") or not isinstance(pool, Mapping):
                        continue
                    queue = self._counter(pool.get("queue"))
                    rejected = self._counter(pool.get("rejected"))
                    if queue is not None:
                        queues.append(queue)
                        valid = True
                    if rejected is not None:
                        rejections[(node_id, pool_name)] = rejected
                        valid = True
            sampled += int(valid)
        if not sampled:
            return None, None
        return {
            "nodes_sampled": sampled,
            "max_cpu_percent": max(cpus) if cpus else None,
            "max_heap_percent": max(heaps) if heaps else None,
            "search_queue": sum(queues) if queues else None,
            "new_search_rejections": 0,
        }, rejections

    def sample(self, force=False):
        """Try one narrow node-stats request, at most once each 30 seconds.

        Permission or unsupported-API failures disable further monitoring for
        this run. Temporary monitoring failures leave searches operational.
        """
        now = time.monotonic()
        with self._condition:
            if self._monitor_disabled or self._sampling:
                return self.snapshot()
            if not force and self._last_sample_at is not None and (
                    now - self._last_sample_at < self.MONITOR_REFRESH_SECONDS):
                return self.snapshot()
            self._sampling = True
            self._last_sample_at = now
        metrics, rejections, failure = None, None, None
        disabled = False
        try:
            monitor = self.es.options(
                request_timeout=self.MONITOR_TIMEOUT_SECONDS,
                max_retries=0, retry_on_timeout=False,
            )
            response = monitor.nodes.stats(
                metric="os,jvm,thread_pool", timeout="2s",
                filter_path=list(self._STATS_FILTER),
            )
            metrics, rejections = self._parse_metrics(self._body(response))
            if metrics is None:
                failure = {"category": "invalid_response"}
        except Exception as error:
            status = self._status(error)
            if status in (401, 403):
                category, disabled = "permission_denied", True
            elif status in (400, 404) or isinstance(error, (AttributeError, NotImplementedError)):
                category, disabled = "unsupported", True
            elif self._is_timeout(error):
                category = "timeout"
            else:
                category = "unavailable"
            failure = {"category": category}
            if status is not None:
                failure["http_status"] = status
        finally:
            with self._condition:
                self._sampling = False
                self._monitor_disabled = disabled
                if failure:
                    self._monitoring["status"] = "unavailable"
                    self._monitoring["failures"] += 1
                    self._monitoring["last_error"] = failure
                else:
                    delta = sum(
                        max(0, rejected - self._rejection_baseline[key])
                        for key, rejected in rejections.items()
                        if key in self._rejection_baseline
                    )
                    self._rejection_baseline = rejections
                    metrics["new_search_rejections"] = delta
                    self._monitoring.update(
                        status="available", last_error=None, last_sample=metrics,
                    )
                    self._monitoring["samples"] += 1
                    if metrics["search_queue"] is not None and metrics["search_queue"] > 0:
                        self._reduce("observed_search_queue", conservative=True)
                    if metrics["max_cpu_percent"] is not None and metrics["max_cpu_percent"] >= 85:
                        self._reduce("observed_high_cpu", conservative=True)
                    if metrics["max_heap_percent"] is not None and metrics["max_heap_percent"] >= 85:
                        self._reduce("observed_high_heap", conservative=True)
                    if delta > 0:
                        self._reduce("new_search_rejections", conservative=True)
                self._condition.notify_all()
        return self.snapshot()

    @classmethod
    def _response_size(cls, response):
        body = cls._body(response)
        if body is None:
            return 0
        # Count encoded JSON without retaining a second full serialized body.
        try:
            encoder = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"))
            return sum(len(piece.encode("utf-8")) for piece in encoder.iterencode(body))
        except (TypeError, ValueError, UnicodeError):
            return 0

    @classmethod
    def _response_signals(cls, response):
        body = cls._body(response)
        if body is None:
            return False, False
        parts = body.get("responses")
        parts = parts if isinstance(parts, list) else [body]
        overloaded, timed_out = False, False
        for part in parts:
            if not isinstance(part, Mapping):
                continue
            overloaded |= cls._status(part) in (429, 503)
            timed_out |= part.get("timed_out") is True
            error = part.get("error")
            if isinstance(error, Mapping):
                overloaded |= error.get("type") == "es_rejected_execution_exception"
            shards = part.get("_shards", {})
            failures = shards.get("failures", []) if isinstance(shards, Mapping) else []
            if isinstance(failures, list):
                for failure in failures:
                    reason = failure.get("reason", {}) if isinstance(failure, Mapping) else {}
                    if isinstance(reason, Mapping):
                        overloaded |= reason.get("type") == "es_rejected_execution_exception"
        return overloaded, timed_out

    def observe(self, response=None, error=None, wall_ms=None, elapsed_ms=None):
        """Observe one completed search request; this function never retries it."""
        # Latency alone does not imply overload or justify smaller pages.
        latency = self._number(wall_ms)
        if latency is None:
            latency = self._number(elapsed_ms)
        size = self._response_size(response) if response is not None else 0
        overloaded, server_timeout = self._response_signals(response)
        overloaded |= self._status(error) in (429, 503)
        client_timeout = self._is_timeout(error)
        with self._condition:
            self._requests_observed += 1
            if latency is not None:
                self._latency["samples"] += 1
                self._latency["last_ms"] = latency
                self._latency["mean_ms"] += (latency - self._latency["mean_ms"]) / self._latency["samples"]
                self._latency["max_ms"] = max(latency, self._latency["max_ms"] or 0)
            self._max_response_bytes = max(self._max_response_bytes, size)
            if overloaded:
                self._overload_responses += 1
                self._reduce("http_overload")
            if client_timeout:
                self._timeouts += 1
                self._reduce("request_timeout")
            if server_timeout:
                self._reduce("search_timeout")
            if size > self.RESPONSE_BYTES_THRESHOLD:
                self._reduce("large_response", page=True)
            if overloaded or client_timeout:
                self._pacing["events"] += 1
                delay = random.uniform(0.1, self.MAX_BACKOFF_SECONDS)
                # Multiple workers cannot accumulate unbounded sleep debt.
                self._next_request_at = max(self._next_request_at, time.monotonic() + delay)

    def before_request(self):
        """Refresh optional metrics when due and apply bounded shared pacing."""
        self.sample()
        with self._condition:
            delay = min(self.MAX_BACKOFF_SECONDS, max(0.0, self._next_request_at - time.monotonic()))
        if delay:
            time.sleep(delay)
            with self._condition:
                self._pacing["waits"] += 1
                self._pacing["total_wait_ms"] += round(delay * 1000, 3)

    def snapshot(self):
        with self._condition:
            return {
                "configured_limits": dict(self._configured),
                "effective_limits": dict(self._limits),
                "monitoring": {
                    **self._monitoring,
                    "last_error": dict(self._monitoring["last_error"]) if self._monitoring["last_error"] else None,
                    "last_sample": dict(self._monitoring["last_sample"]) if self._monitoring["last_sample"] else None,
                },
                "signals": list(self._signals),
                "adjustments": [{"reason": item["reason"], "before": dict(item["before"]),
                                 "after": dict(item["after"])} for item in self._adjustments],
                "requests_observed": self._requests_observed,
                "active_requests": self._active_requests,
                "max_observed_requests": self._max_active_requests,
                "timeouts": self._timeouts,
                "overload_responses": self._overload_responses,
                "max_response_bytes": self._max_response_bytes,
                "pacing": dict(self._pacing),
                "latency": {
                    "samples": self._latency["samples"],
                    "last_ms": round(self._latency["last_ms"], 3) if self._latency["last_ms"] is not None else None,
                    "max_ms": round(self._latency["max_ms"], 3) if self._latency["max_ms"] is not None else None,
                    "mean_ms": round(self._latency["mean_ms"], 3) if self._latency["samples"] else None,
                },
            }

    report = snapshot


RuntimeController = EndpointRuntimeController
