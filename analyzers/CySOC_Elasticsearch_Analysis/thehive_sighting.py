"""Resolve and update one observable in the originating TheHive 4 case.

The caller is responsible for requiring positive, valid analyzer evidence for
sighting, selecting generated tags, and handling missing TheHive configuration. The dynamic Cortex input
``message`` supplies a case number (or an internal case ID on early 4.0).
This module never searches across cases, changes IOC state, clears sighted, or
follows redirects.
"""

import json
import math
import re
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


class SightingError(RuntimeError):
    """A safe diagnostic which contains no credentials or observable content."""

    def __init__(self, message, *, code="thehive_sighting_failed", http_status=None):
        super().__init__(message)
        self.code = code
        self.http_status = http_status


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _deployment_url(base_url):
    if not isinstance(base_url, str) or not base_url or any(ord(c) < 32 for c in base_url):
        raise SightingError("TheHive URL must be an HTTP(S) deployment URL", code="invalid_configuration")
    try:
        parsed = urlsplit(base_url)
        valid = (parsed.scheme in {"http", "https"} and parsed.hostname
                 and parsed.username is None and parsed.password is None
                 and not parsed.query and not parsed.fragment
                 and (parsed.port is None or 1 <= parsed.port <= 65535))
    except ValueError:
        valid = False
    if not valid:
        raise SightingError("TheHive URL must use HTTP(S) without embedded credentials, query, or fragment", code="invalid_configuration")
    path = parsed.path.rstrip("/")
    for suffix in ("/api/v1", "/api"):
        if path.endswith(suffix):
            path = path[:-len(suffix)]
            break
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _validate_identity(observable, observable_id, data_type, data):
    if not isinstance(observable, dict):
        raise SightingError("TheHive returned an invalid observable response", code="thehive_invalid_response")
    if observable.get("_id") != observable_id or ("id" in observable and observable["id"] != observable_id):
        raise SightingError("TheHive observable ID does not match the originating observable", code="observable_identity_mismatch")
    if observable.get("dataType") != data_type or observable.get("data") != data:
        raise SightingError("TheHive observable type or value does not match the analyzer input", code="observable_identity_mismatch")
    if not isinstance(observable.get("sighted"), bool):
        raise SightingError("TheHive observable has no valid sighted status", code="thehive_invalid_response")


def _safe_id(value):
    return (isinstance(value, str) and bool(value) and len(value) <= 512
            and value not in {".", ".."}
            and not any(c.isspace() or ord(c) < 32 or ord(c) == 127
                        or c in "/\\?#" for c in value))


def _case_context(case_reference):
    if case_reference is None or case_reference == "":
        raise SightingError("The analyzer input has no originating case context", code="missing_case_context")
    if (not isinstance(case_reference, str) or len(case_reference) > 128
            or not re.fullmatch(r"(?:[0-9]+|~[0-9]+)", case_reference)
            or (not case_reference.startswith("~") and int(case_reference) <= 0)):
        raise SightingError("The analyzer case context must be a case number or internal case ID", code="invalid_case_context")
    return case_reference


def update_observable(*, base_url, api_key, case_reference, data_type, data,
                      mark_sighted=False, tags=(), organisation=None,
                      request_timeout=30, verify_ssl=True, ca_file=None,
                      transport=None, request_context=None):
    """Apply optional sighting and tags with one verified case-scoped lookup.

    ``case_reference`` is the dynamic Cortex input ``message``, never a static
    analyzer setting. ``organisation`` is the optional dynamically forwarded
    TheHive organisation name. Exactly one case-scoped observable must match
    the input type and value before its identity is checked again with GET.
    ``transport(method, path, body)`` is an optional testing seam, returning
    decoded JSON objects/lists or None for a successful HTTP 204 PATCH.
    Early TheHive 4 releases require the legacy observable route. Only a 404
    from the initial v1 observable GET permits a legacy GET; any PATCH uses
    the route whose GET succeeded, with no write fallback or retry.
    Both changes share the fresh observable GET and at most one PATCH. Existing
    tags are preserved and a request whose changes are already present performs
    no write. TheHive 4 replaces the complete tag list: a concurrent tag edit
    after the fresh GET can still race with this PATCH. No automatic retries
    occur. The legacy TheHive 4.0 observable route rewrites colon/dot tag names;
    requested tags are reported unsupported on that route without writing tags.
    A sighting request can still proceed through the verified legacy route.
    Exceptions are sanitized SightingError instances for the caller's separate
    sighting diagnostics; search evidence and status must be retained.
    ``request_context`` optionally receives the effective deployment and
    organisation, including when the case lookup fails. Without an explicit
    organisation, a best-effort current-user lookup discovers the API account's
    default context and pins it for subsequent requests. Diagnostic lookup
    failure leaves the original unheaded request behavior intact.
    """
    if request_context is not None and not isinstance(request_context, dict):
        raise SightingError("TheHive request context must be an object", code="invalid_configuration")
    if not isinstance(mark_sighted, bool):
        raise SightingError("TheHive sighting request must be boolean", code="invalid_configuration")
    if (not isinstance(tags, (list, tuple))
            or any(not isinstance(tag, str) or not tag.strip() for tag in tags)):
        raise SightingError("TheHive requested tags must be a list of nonempty strings", code="invalid_configuration")
    requested_tags = list(dict.fromkeys(tags))
    deployment = _deployment_url(base_url)
    if request_context is not None:
        request_context["thehive_url"] = deployment
    if not isinstance(api_key, str) or not api_key or any(c.isspace() or ord(c) < 32 for c in api_key):
        raise SightingError("A nonempty TheHive API key is required", code="invalid_configuration")
    case_reference = _case_context(case_reference)
    if not isinstance(data_type, str) or not data_type or not isinstance(data, str):
        raise SightingError("The analyzer input must provide a data type and string value", code="invalid_configuration")
    if organisation is not None and (not isinstance(organisation, str) or not organisation.strip()
            or len(organisation) > 512 or any(ord(c) < 32 or ord(c) == 127 for c in organisation)):
        raise SightingError("TheHive organisation context is invalid", code="invalid_organisation_context")
    if request_context is not None and organisation is not None:
        request_context.update(organisation=organisation, organisation_header=organisation,
                               organisation_resolution={"status": "provided", "reason_codes": []})
        if not request_context.get("organisation_source"):
            request_context["organisation_source"] = "parameters.organisation"
    if (isinstance(request_timeout, bool) or not isinstance(request_timeout, (int, float))
            or not math.isfinite(request_timeout) or request_timeout <= 0):
        raise SightingError("TheHive request timeout must be a positive number of seconds", code="invalid_configuration")
    if not isinstance(verify_ssl, bool):
        raise SightingError("TheHive certificate verification setting must be boolean", code="invalid_configuration")
    if not verify_ssl and ca_file:
        raise SightingError("A TheHive CA file cannot be combined with disabled certificate verification", code="invalid_configuration")
    case_path = "/api/v1/case/" + quote(case_reference, safe="")
    current_user_paths = ("/api/v1/user/current", "/api/user/current")
    query_path = "/api/v1/query"
    query_body = None
    observable_path = None
    patch_body = None

    if transport is None:
        try:
            context = ssl.create_default_context(cafile=ca_file) if verify_ssl else ssl._create_unverified_context()
            opener = build_opener(_NoRedirects(), HTTPSHandler(context=context))
        except (OSError, ValueError, TypeError):
            raise SightingError("TheHive TLS/CA configuration could not be loaded", code="invalid_configuration") from None

        def transport(method, request_path, body):
            # This narrowly scoped closure has no general-purpose write route.
            allowed = ((method == "GET" and request_path == case_path and body is None)
                       or (method == "GET" and request_path in current_user_paths
                           and request_context is not None and body is None)
                       or (method == "POST" and request_path == query_path
                           and query_body is not None and body == query_body)
                       or (observable_path is not None and request_path == observable_path
                           and ((method == "GET" and body is None)
                                or (method == "PATCH" and patch_body is not None
                                    and body == patch_body))))
            if not allowed:
                raise SightingError("Unsupported TheHive sighting request", code="invalid_configuration")
            payload = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers = {"Accept": "application/json", "Content-Type": "application/json",
                       "Authorization": "Bearer " + api_key}
            if organisation is not None:
                headers["X-Organisation"] = organisation
            request = Request(deployment + request_path, data=payload, method=method,
                              headers=headers)
            try:
                with opener.open(request, timeout=float(request_timeout)) as response:
                    raw = response.read(16 * 1024 * 1024 + 1)
            except HTTPError as error:
                status = error.code
                try:
                    error.close()
                except Exception:
                    pass
                message = "TheHive rejected an HTTP redirect" if 300 <= status < 400 else "TheHive returned HTTP {}".format(status)
                raise SightingError(message, code="thehive_http_error", http_status=status) from None
            except (TimeoutError, URLError, OSError) as error:
                reason = getattr(error, "reason", error)
                if isinstance(reason, TimeoutError):
                    raise SightingError("TheHive request timed out", code="thehive_timeout") from None
                if isinstance(reason, ssl.SSLError):
                    raise SightingError("TheHive TLS verification failed", code="thehive_tls_error") from None
                raise SightingError("TheHive connection failed", code="thehive_connection_error") from None
            if len(raw) > 16 * 1024 * 1024:
                raise SightingError("TheHive response exceeded the size limit", code="thehive_invalid_response")
            if not raw and method == "PATCH":
                return None
            try:
                return json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                raise SightingError("TheHive returned invalid JSON", code="thehive_invalid_response") from None

    def call(method, path, body=None):
        try:
            return transport(method, path, body)
        except SightingError:
            raise
        except Exception:
            # Custom transports can expose URLs, observable content, or secrets
            # through arbitrary exception text. Never propagate their wording.
            raise SightingError("TheHive request failed", code="thehive_connection_error") from None

    if request_context is not None and organisation is None:
        request_context.update(organisation=None, organisation_header=None,
                               organisation_source="api_key_default")
        try:
            try:
                current_user = call("GET", current_user_paths[0])
            except SightingError as error:
                if error.http_status != 404:
                    raise
                current_user = call("GET", current_user_paths[1])
            default_organisation = current_user.get("organisation") if isinstance(current_user, dict) else None
            if (not isinstance(default_organisation, str) or not default_organisation.strip()
                    or len(default_organisation) > 512
                    or any(ord(c) < 32 or ord(c) == 127 for c in default_organisation)):
                raise SightingError("TheHive current user response has no valid organisation",
                                    code="thehive_invalid_response")
            # The current-user response describes the actual unheaded request
            # context. Pin that same organisation to avoid a changed account
            # default between diagnostic and observable requests.
            organisation = default_organisation
            request_context.update(organisation=organisation, organisation_header=organisation,
                                   organisation_resolution={"status": "resolved", "reason_codes": []})
        except SightingError as error:
            resolution = {"status": "failed", "reason_codes": [error.code],
                          "reason": str(error).replace(api_key, "[REDACTED]")}
            if error.http_status is not None:
                resolution["http_status"] = error.http_status
            request_context["organisation_resolution"] = resolution

    if request_context is not None:
        request_context["case_lookup_url"] = deployment + case_path
    try:
        case = call("GET", case_path)
    except SightingError as error:
        if error.http_status == 404:
            raise SightingError("The originating TheHive case was not found", code="case_not_found", http_status=404) from None
        raise
    if not isinstance(case, dict) or not _safe_id(case.get("_id")):
        raise SightingError("TheHive returned an invalid case response", code="thehive_invalid_response")
    resolvedcase_id = case["_id"]
    if "id" in case and case["id"] != resolvedcase_id:
        raise SightingError("TheHive case ID does not match the originating case", code="case_identity_mismatch")
    if case_reference.startswith("~"):
        if resolvedcase_id != case_reference:
            raise SightingError("TheHive case ID does not match the analyzer case context", code="case_identity_mismatch")
    else:
        number = case.get("number")
        if (isinstance(number, bool) or not isinstance(number, int)
                or number != int(case_reference)):
            raise SightingError("TheHive case number does not match the analyzer case context", code="case_identity_mismatch")

    query_body = {"query": [
        {"_name": "getCase", "idOrName": resolvedcase_id},
        {"_name": "observables"},
        {"_name": "filter", "_and": [
            {"_eq": {"_field": "dataType", "_value": data_type}},
            {"_eq": {"_field": "data", "_value": data}},
        ]},
        {"_name": "page", "from": 0, "to": 2, "extraData": []},
    ]}
    candidates = call("POST", query_path, query_body)
    if not isinstance(candidates, list):
        raise SightingError("TheHive returned an invalid observable query response", code="thehive_invalid_response")
    if not candidates:
        raise SightingError("No matching observable exists in the originating TheHive case", code="observable_not_found")
    if len(candidates) != 1:
        raise SightingError("More than one matching observable exists in the originating TheHive case", code="ambiguous_observable")
    candidate = candidates[0]
    if not isinstance(candidate, dict) or not _safe_id(candidate.get("_id")):
        raise SightingError("TheHive returned an invalid observable query response", code="thehive_invalid_response")
    observable_id = candidate["_id"]
    _validate_identity(candidate, observable_id, data_type, data)
    observable_path = "/api/v1/observable/" + quote(observable_id, safe="")
    legacy_route = False
    try:
        observable = call("GET", observable_path)
    except SightingError as error:
        if error.http_status != 404:
            raise
        # TheHive 4.0 has v1 case/query APIs, but its observable GET/PATCH
        # routes are still exposed through the v0 compatibility API. Resolve
        # that route with GET before allowing the single observable write.
        observable_path = "/api/case/artifact/" + quote(observable_id, safe="")
        legacy_route = True
        observable = call("GET", observable_path)
    _validate_identity(observable, observable_id, data_type, data)
    unsupported_legacy_tags = bool(legacy_route and requested_tags)
    existing_tags = observable.get("tags", [])
    if requested_tags and not unsupported_legacy_tags and (not isinstance(existing_tags, list)
                           or any(not isinstance(tag, str) for tag in existing_tags)):
        raise SightingError("TheHive observable has an invalid tag list", code="thehive_invalid_response")
    tags_added = [] if unsupported_legacy_tags else [tag for tag in requested_tags if tag not in existing_tags]
    patch_body = {}
    if mark_sighted and not observable["sighted"]:
        patch_body["sighted"] = True
    if tags_added:
        patch_body["tags"] = list(dict.fromkeys(existing_tags + tags_added))
    outcome = {
        "case_reference": case_reference, "resolvedcase_id": resolvedcase_id,
        "observable_id": observable_id,
        "sighted": {"status": ("updated" if "sighted" in patch_body else "already_sighted")
                               if mark_sighted else "skipped",
                    "sighted": bool(mark_sighted or observable["sighted"])},
        "tagging": {"status": ("updated" if tags_added else "already_present")
                              if requested_tags else "skipped",
                    "tags_requested": requested_tags, "tags_added": tags_added},
    }
    if unsupported_legacy_tags:
        outcome["tagging"].update(
            status="failed", reason_codes=["unsupported_legacy_tag_format"],
            reason="TheHive 4.0 rewrites colon/dot tag names; preserving these tags requires the v1 observable API (TheHive 4.1).",
        )
    if not patch_body:
        return outcome
    result = call("PATCH", observable_path, patch_body)
    if result is not None:
        if not isinstance(result, dict) or result.get("error") or result.get("type") in {"AuthenticationError", "AuthorizationError", "NotFoundError", "BadRequest"}:
            raise SightingError("TheHive returned an invalid update response", code="thehive_invalid_response")
        # A deployment which returns the updated object must confirm the same
        # identity and true state. The documented API instead returns HTTP 204.
        if any(key in result for key in ("_id", "dataType", "data", "sighted")):
            _validate_identity(result, observable_id, data_type, data)
            if mark_sighted and result["sighted"] is not True:
                raise SightingError("TheHive did not confirm the sighted update", code="thehive_invalid_response")
        if tags_added and ("tags" in result or any(key in result for key in ("_id", "dataType", "data", "sighted"))):
            confirmed = result.get("tags")
            if (not isinstance(confirmed, list) or any(not isinstance(tag, str) for tag in confirmed)
                    or any(tag not in confirmed for tag in patch_body["tags"])):
                raise SightingError("TheHive did not confirm the tag update", code="thehive_invalid_response")
    return outcome


def mark_observable_sighted(*, base_url, api_key, case_reference, data_type, data,
                            organisation=None, request_timeout=30, verify_ssl=True,
                            ca_file=None, transport=None, request_context=None):
    """Backward-compatible sighting-only wrapper with the original result shape."""
    result = update_observable(
        base_url=base_url, api_key=api_key, case_reference=case_reference,
        data_type=data_type, data=data, mark_sighted=True,
        organisation=organisation, request_timeout=request_timeout,
        verify_ssl=verify_ssl, ca_file=ca_file, transport=transport,
        request_context=request_context,
    )
    return {key: result[key] for key in ("case_reference", "resolvedcase_id", "observable_id")} | result["sighted"]
