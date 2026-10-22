#!/usr/bin/env python3
"""Cortex Elasticsearch analyzer with bounded searches and optional PIT paging.

Python 3.13+; elasticsearch-py 8.19.x for Elasticsearch 8, or matching 9.x client
for Elasticsearch 9; cortexutils and python-dateutil.

Search fields are configured as multi-value lists per field group: ip_fields,
domain_fields, url_fields, hostname_fields, email_fields, filename_fields,
hash_fields, username_fields, email_subject_fields, user_agent_fields, and
process_args_fields. Each defaults to its ECS field list below. Missing/null
groups use these defaults; an explicitly empty group stays empty. Custom field
names belong directly in the relevant group. FQDN searches join domain_fields
and url_fields; filename searches join filename_fields and process_args_fields.
Field groups are configuration-only, replacing field and query_fields_by_type.

Other search keys can be supplied in config or as per-job parameters
(parameters wins): lookback_days, pit_threshold, pit_keep_alive,
track_total_hits, field_retrieval, include_report_fields, return_fields,
search_concurrency, max_concurrent_shard_requests, sort_order, search_timeout, request_timeout,
max_retries, mark_sighted_on_hits, add_tags_to_observable, data_view_id,
kibana, debug.

lookback_days=0 means no time filter; 30 means a rolling 30-day interval ending
at the analyzer's start time. size remains the maximum hits per index pattern.
Search selection always uses an ordinary response first and opens a PIT only when more
results need pagination. pit_threshold (default 500) bounds ordinary probes and
PIT pages; runtime pressure can reduce concurrency, shard requests and page size.
pit_keep_alive (default 10m) is snapshot retention BETWEEN requests, not a query
timeout. PIT pages use search_after and renew/close the latest PIT identifier.
One lost-PIT restart begins with a fresh snapshot and discards the prior attempt.
sort_order defaults to desc (newest first); asc retrieves oldest first. Both
directions keep missing timestamps last, including the merged report output.

field_retrieval: source (filtered _source, default), fields (_source:false and
fields), docvalues (_source:false and mapping-checked docvalue_fields). Returned
fields are the query fields plus @timestamp, optional report fields and explicit
return_fields. Only docvalues can avoid loading normal mapped fields' _source
on the server. Doc values can reorder/deduplicate arrays; use source when their
original order matters. PIT provides consistency, not a guaranteed speedup.

full.tags contains unique tags from the analyzed IP observable and retained
hits. IP classification is performed once using Python's ipaddress properties;
overlapping true properties each produce a tag. Explicit return_fields enable
event tags: data_stream requires its type, dataset and namespace in the same
hit; observer supports only product, vendor, version and id. Parent object
names retain descendants in returned fields; fields/docvalues expand these two
object roots to descendant wildcards. Retrieval is independent of the tagging
allowlist, and docvalues still rejects unsupported mapped descendants.
add_tags_to_observable defaults to true and requests one AddTagToArtifact report
operation per unique tag. TheHive applies these additive operations to the job's
originating observable; no API key, URL or case lookup is needed for tagging.
Native analyzer operation processing was verified against TheHive 4.1.24 source.
Operation generation and report output support cortexutils 2.1.0 and 2.2.1;
the complete envelope is written explicitly rather than relying on SDK helpers.
The report records tagging as requested, with application unconfirmed, because
TheHive executes the operations after receiving the report. Sighting still uses
the optional direct API path and its failures do not suppress tag operations.
Extracted IP artifacts receive their own classification plus supported event
tags from only the retained hits containing that IP. Canonical IPs and tags are
deduplicated; classification is cached once per unique IP, reusing the analyzed
IP's result. All extracted artifacts explicitly use Cortex/TheHive 4 TLP:RED=3.
The analyzed observable itself is omitted from artifacts using matching type
and value, with canonical IP comparison. Its hits and report tags remain, and
AddTagToArtifact operations update its existing TheHive observable separately.

IP reports include optional original and NAT IPs and ports for source,
destination, client and server. include_report_fields requests this context by default; disabling
it keeps only fields already selected or explicitly requested in return_fields.
The IP context aliases are independent of query fields, tag rules and artifacts.

full.search.status: complete, partial, failed. complete means all requested
searches executed without errors. retrieval_complete and results_truncated
separately describe evidence coverage within the size cap; null means unknown.
Per-query reasons, counts, timings, shard status and PIT cleanup are retained.
Invalid configuration returns a Cortex error (success:false). Searches that
run still produce diagnostic reports; their search taxonomy and full.search
status describe actual Elasticsearch success, including partial evidence.
endpoint_id contains the full configured Elasticsearch URL with credentials,
query and fragment removed. Host pools list every configured URL, comma-separated;
this identifies the configured pool, not the node that answered each page.
endpoint_profile is a numeric connection-profile ordinal, keeping repeated URLs
with different credentials distinct for evidence deduplication and artifact tags.

Sighting requires configuration-only TheHive URL/API key and the dynamic case
context TheHive 4 sends in input.message (case number, or an internal case ID
in early 4.0). Resolve only within that case and require one exact observable
type/value match. Only positive returned evidence triggers the optional update;
its separate full.search.sighting diagnostics never overwrite Elasticsearch
coverage. thehive_sighting.py must be installed beside this script.
debug=true enables full.debug, recording the original job submission (credentials redacted), deployment
URL and effective organisation, including failed case lookups. The original
message, config and parameters are retained without injecting local defaults.
Only parameters.organisation selects an explicit organisation. Without it, a
best-effort current-user lookup resolves the API key's default organisation;
that name is then used for the update requests. Resolution failure is reported
explicitly and does not replace the observable update's outcome. debug defaults
to false, which omits full.debug entirely.

max_retries>0 enables transport timeout retries; 0 disables them. There is no
separate retry_on_timeout configuration parameter.

full.search.kibana carries the backend-selected observable type, fields, KQL,
URL and time scope. A configured dashboard is retained; otherwise the link opens
Discover with the selected timestamp sort and Kibana's default data view.
full.search.query_field_groups identifies the configuration
groups used by the search; report-only return fields never expand the query.
Each retained hit can carry kibana_document_url for its Evidence title icon.
Configure optional kibana for query, dashboard and document
links (empty disables all Kibana links) and data_view_id (default logs-*).
Each view/index/document ID is URL-encoded; full.search.kibana.base_url records
the shared base URL used by every Kibana link.

Run --print-configuration-items to obtain items to merge into the existing
Cortex analyzer definition. Keep baseConfig/name/command aligned with the
Elasticsearch_Analysis installation directory.
"""

import fnmatch
import ipaddress
import json
import re
import sys
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from dataclasses import dataclass
from decimal import Decimal
from datetime import datetime, timedelta, timezone
from time import perf_counter
from urllib.parse import quote, urlsplit, urlunsplit

import dateutil.parser
from cortexutils.analyzer import Analyzer
from cortexutils.worker import Worker
from elasticsearch import Elasticsearch, VERSION as ES_VERSION
from thehive_sighting import SightingError, mark_observable_sighted
from search_runtime import EndpointRuntimeController

ANALYZER_REVISION = "2026-10-22.1"
MIN_PYTHON_VERSION = (3, 13)
CORTEX_TLP_RED = 3

# support ECS
DOMAIN = [
    f"{x}.{y}"
    for x in [
        "client",
        "destination",
        "server",
        "source",
        "url",
    ]
    for y in [
        "domain",
        "registered_domain"
    ]
] + [
    "dns.answers.name",
    "dns.question.name",
    "dns.question.registered_domain",
]

FILENAME = [
    "dll.pe.original_file_name",
    "email.attachments.file.name",
    "file.name",
    "file.pe.original_file_name",
    "process.name",
    "process.parent.name",
    "process.pe.original_file_name",
    "process.parent.pe.original_file_name",
    "process.session_leader.name",
    "process.parent.session_leader.name",
    "process.entry_leader.name",
    "process.parent.entry_leader.name",
    "process.group_leader.name",
    "process.parent.group_leader.name",
]

HASH = [
    f"{x}.{y}"
    for x in [
        "hash",
        "dll.hash",
        "email.attachments.file.hash",
        "file.hash",
        "process.hash",
        "process.parent.hash",
    ]
    for y in [
        "cdhash",
        "imphash",
        "md5",
        "pehash",
        "sha1",
        "sha256",
        "sha384",
        "sha512",
        "ssdeep",
        "tlsh",
    ]
] + [
    f"{x}.{y}"
    for x in [
        "dll.code_signature",
        "file.code_signature",
        "process.code_signature",
        "process.parent.code_signature",
    ]
    for y in [
        "thumbprint_sha256",
    ]
] + [
    f"{x}.{y}"
    for x in [
        "tls.client.hash",
        "tls.server.hash",
    ]
    for y in [
        "md5",
        "sha1",
        "sha256",
    ]
] + [
    f"{x}.{y}"
    for x in [
        "dll.pe",
        "file.pe",
        "process.pe",
        "process.parent.pe",
    ]
    for y in [
        "imphash",
        "pehash",
    ]
] + [
    "user.hash"
]

HOSTNAME = [
    "host.name",
]

IP = [
    "client.ip",
    "client.nat.ip",
    "destination.ip",
    "destination.nat.ip",
    "dns.resolved_ip",
    "network.forwarded_ip",
    "orchestrator.resource.ip",
    "related.ip",
    "server.ip",
    "server.nat.ip",
    "source.ip",
    "source.nat.ip",
]

MAIL = [
    "client.user.email",
    "destination.user.email",
    "source.user.email",
    "user.changes.email",
    "user.effective.email",
    "user.email",
    "user.target.email",
]

MAIL_SUBJECT = [
    "email.subject",
]

PROCESS_ARGS = [
    "process.args",
]

URL = [
    "url.path",
    "url.full",
    "url.original",
]

USERNAME = [
    f"{x}.{y}"
    for x in [
        "client.user",
        "destination.user",
        "process.attested_user",
        "process.real_user",
        "process.saved_user",
        "process.user",
        "server.user",
        "source.user",
        "user.changes",
        "user.effective",
        "user.target"
    ]
    for y in [
        "email",
        "id",
        "name"
    ]
] + [
    "url.username",
    "user.name",
    "user.id",
    "user.email",
]

USER_AGENT = [
    "user_agent.name",
    "user_agent.original",
]

MAIL = list(dict.fromkeys(MAIL + [name for name in USERNAME if name.endswith(".email")]))


FIELD_GROUP_DEFINITIONS = (
    ("ip_fields", "string", tuple(dict.fromkeys(IP)), "Fields to query for IP observables.", True),
    ("domain_fields", "string", tuple(dict.fromkeys(DOMAIN)), "Fields to query for domain observables; also used for FQDN observables.", True),
    ("url_fields", "string", tuple(dict.fromkeys(URL)), "Fields to query for URL observables; also used for FQDN observables.", True),
    ("hostname_fields", "string", tuple(dict.fromkeys(HOSTNAME)), "Fields to query for hostname observables.", True),
    ("email_fields", "string", tuple(dict.fromkeys(MAIL)), "Fields to query for mail/email-address observables.", True),
    ("filename_fields", "string", tuple(dict.fromkeys(FILENAME)), "Fields to query for filename observables, together with process_args_fields.", True),
    ("hash_fields", "string", tuple(dict.fromkeys(HASH)), "Fields to query for hash observables.", True),
    ("username_fields", "string", tuple(dict.fromkeys(USERNAME)), "Fields to query for username observables.", True),
    ("email_subject_fields", "string", tuple(dict.fromkeys(MAIL_SUBJECT)), "Fields to query for mail-subject observables.", True),
    ("user_agent_fields", "string", tuple(dict.fromkeys(USER_AGENT)), "Fields to query for user-agent observables.", True),
    ("process_args_fields", "string", tuple(dict.fromkeys(PROCESS_ARGS)), "Additional process argument fields to query for filename observables.", True),
)

OBSERVABLE_FIELD_GROUPS = {
    "ip": ("ip_fields",), "domain": ("domain_fields",), "url": ("url_fields",),
    "hostname": ("hostname_fields",), "mail": ("email_fields",),
    "filename": ("filename_fields", "process_args_fields"),
    "hash": ("hash_fields",), "username": ("username_fields",),
    "mail-subject": ("email_subject_fields",), "user-agent": ("user_agent_fields",),
    "fqdn": ("domain_fields", "url_fields"),
}


def default_field_groups():
    """Return independent copies of the configured ECS field-group defaults."""
    return {definition[0]: list(definition[2]) for definition in FIELD_GROUP_DEFINITIONS}


def query_field_group_names(data_type):
    if data_type not in OBSERVABLE_FIELD_GROUPS:
        raise ValueError("Unsupported observable type: {}".format(data_type))
    return list(OBSERVABLE_FIELD_GROUPS[data_type])


def observable_field_groups():
    """Describe default query fields by observable type, without configuration."""
    defaults = default_field_groups()
    return {data_type: list(dict.fromkeys(field for name in group_names for field in defaults[name]))
            for data_type, group_names in OBSERVABLE_FIELD_GROUPS.items()}



REPORT_FIELD_MAP = {
    "process_parent_name": "process.parent.name", "process_name": "process.name",
    "process_args": "process.args", "user_name": "user.name", "host_name": "host.name",
    "destination_ip": "destination.ip", "destination_port": "destination.port",
    "source_ip": "source.ip", "source_port": "source.port",
    "source_user_name": "source.user.name", "url_domain": "url.domain",
    "url_path": "url.path", "url_full": "url.full", "rule_category": "rule.category",
    "dns_question_name": "dns.question.name", "dns_resolvedip": "dns.resolved_ip",
    "event_action": "event.action",
}

IP_REPORT_FIELD_MAP = {
    "source_nat_ip": "source.nat.ip",
    "source_nat_port": "source.nat.port",
    "destination_nat_ip": "destination.nat.ip",
    "destination_nat_port": "destination.nat.port",
    "client_ip": "client.ip", "client_nat_ip": "client.nat.ip",
    "client_port": "client.port", "client_nat_port": "client.nat.port",
    "server_ip": "server.ip", "server_nat_ip": "server.nat.ip",
    "server_port": "server.port", "server_nat_port": "server.nat.port",
}

OPTION_DEFINITIONS = (
    ("lookback_days", "number", 0, "Days back from job start; 0 searches all retained data."),
    ("pit_threshold", "number", 500, "Automatic ordinary-search threshold and maximum PIT page size, from 1 to 10000. Runtime pressure can reduce page size."),
    ("pit_keep_alive", "string", "10m", "PIT retention between requests, e.g. 10m; cover processing, retry and backoff delays. Not a query timeout."),
    ("track_total_hits", "string", "200", "Accurate-count threshold: integer, true for exact, false to disable."),
    ("field_retrieval", "string", "source", "source, fields, or docvalues; see module documentation."),
    ("include_report_fields", "boolean", True, "Return existing report fields as well as query fields and timestamp."),
    ("return_fields", "string", [], "Additional returned field names, object roots or patterns. Requested data_stream and observer fields enable the supported event tags; other fields only add report data.", True),
    ("search_concurrency", "number", 2, "Maximum concurrent index-pattern searches per endpoint, from 1 to 8. Runtime pressure can reduce concurrency."),
    ("max_concurrent_shard_requests", "number", 3, "Maximum concurrent shard requests per node for each search. Runtime pressure can reduce this ceiling."),
    ("sort_order", "string", "desc", "Timestamp search order: desc retrieves newest first (default); asc retrieves oldest first. Missing timestamps are last."),
    ("search_timeout", "string", "30s", "Server search timeout for each page/sub-search."),
    ("request_timeout", "number", 60, "Client request timeout in seconds; must exceed search_timeout."),
    ("max_retries", "number", 3, "Maximum retries per HTTP request, including timeouts. 0 disables retries; 3 allows up to 4 total attempts."),
    ("mark_sighted_on_hits", "boolean", True, "Mark the matching observable in the originating TheHive 4 case sighted when valid hits are returned. Requires TheHive credentials and the dynamic case context in input.message; ambiguous matches are not updated."),
    ("add_tags_to_observable", "boolean", True, "Request AddTagToArtifact operations for the unique report tags. TheHive applies them to the originating observable when processing the report; no TheHive API credentials or case lookup are needed for tagging. IP classification tags can be requested without search hits."),
    ("data_view_id", "string", "logs-*", "Kibana data-view ID used for document links. This is the saved data-view ID, not the analyzer's matched index patterns."),
    ("kibana", "string", "", "Shared Kibana base URL for query, dashboard and document links, including any reverse-proxy or /s/<space> path. Leave empty to disable all Kibana links; omit app paths, query and fragment."),
    ("debug", "boolean", False, "Include full.debug with the submitted job configuration (credentials redacted), TheHive URL and effective organisation. False omits the debug field entirely."),
)

SIGHTING_CONFIGURATION_DEFINITIONS = (
    ("thehive_url", "string", "", "TheHive deployment URL for observable sighting; configuration only. Native tag operations do not use it."),
    ("thehive_api_key", "string", "", "TheHive API key with manageObservable permission for sighting. Native tag operations need no API key. Keep in Cortex configuration; never supply in job parameters."),
    ("thehive_verifyssl", "boolean", True, "Verify the TheHive server TLS certificate."),
    ("thehive_cert_path", "string", "", "Optional CA certificate path for TheHive; otherwise use the system trust store."),
)


def configuration_items():
    required_groups = {"domain_fields", "url_fields", "hostname_fields", "email_fields",
                       "filename_fields", "hash_fields", "username_fields", "email_subject_fields",
                       "user_agent_fields", "process_args_fields"}
    items = []
    for definition in FIELD_GROUP_DEFINITIONS + OPTION_DEFINITIONS + SIGHTING_CONFIGURATION_DEFINITIONS:
        name, value_type, default, description = definition[:4]
        item = {"name": name, "type": value_type, "required": name in required_groups,
                "multi": len(definition) > 4 and definition[4], "description": description}
        if definition in FIELD_GROUP_DEFINITIONS:
            item["defaultValue"] = list(default)
        elif not item["multi"]:
            item["defaultValue"] = default
        items.append(item)
    return items


def utc_string(value):
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def string_list(value, name, optional=False):
    if value is None and optional:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)) or (not value and not optional):
        raise ValueError("{} must be a nonempty list or string".format(name))
    if optional:
        # Cortex can serialize an unfilled optional multi-value input as "",
        # [""], or null entries. These placeholders do not name requested fields.
        value = [v for v in value if v is not None and not (isinstance(v, str) and not v.strip())]
    if any(not isinstance(v, str) or not v.strip() for v in value):
        raise ValueError("{} contains an empty or invalid string".format(name))
    return list(dict.fromkeys(v.strip() for v in value))


def boolean(value, name):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true"
    raise ValueError("{} must be true or false".format(name))


def integer(value, name, minimum=1, maximum=None):
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)):
        raise ValueError("{} must be an integer".format(name))
    value = int(value)
    if value < minimum or (maximum is not None and value > maximum):
        raise ValueError("{} is outside its permitted range".format(name))
    return value


def duration_seconds(value, name):
    match = re.fullmatch(r"([1-9][0-9]*)(nanos|micros|ms|s|m|h|d)", str(value))
    if not match:
        raise ValueError("{} needs a positive Elasticsearch duration, e.g. 2m or 30s".format(name))
    scale = {"nanos": 1e-9, "micros": 1e-6, "ms": .001, "s": 1, "m": 60, "h": 3600, "d": 86400}
    return int(match[1]) * scale[match[2]]


class ConfigurationError(ValueError):
    """Invalid local configuration; fail the Cortex job rather than report success."""


def require_python_version(version=None):
    """Fail before searching when the analyzer runs on an unsupported Python."""
    current = sys.version_info if version is None else version
    if tuple(current[:2]) < MIN_PYTHON_VERSION:
        raise ConfigurationError("Python 3.13 or newer is required; running {}.{}".format(*current[:2]))


def validate_kibana_url(value):
    """Validate the shared optional base for query, dashboard and document links."""
    if value is None or value == "":
        return ""
    message = "kibana must be an HTTP(S) base URL without credentials, query, fragment, whitespace or backslashes"
    if not isinstance(value, str) or any(c.isspace() or ord(c) < 32 or ord(c) == 127 or c == "\\" for c in value):
        raise ValueError(message)
    try:
        parsed = urlsplit(value)
        valid = (parsed.scheme in ("http", "https") and parsed.hostname
                 and parsed.username is None and parsed.password is None
                 and "?" not in value and "#" not in value
                 and (parsed.port is None or 1 <= parsed.port <= 65535))
    except ValueError:
        valid = False
    if not valid:
        raise ValueError(message)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


@dataclass(frozen=True)
class Settings:
    lookback_days: int = 0
    pit_threshold: int = 500
    pit_keep_alive: str = "10m"
    track_total_hits: object = 200
    field_retrieval: str = "source"
    include_report_fields: bool = True
    return_fields: tuple = ()
    search_concurrency: int = 2
    max_concurrent_shard_requests: int = 3
    sort_order: str = "desc"
    search_timeout: str = "30s"
    request_timeout: int = 60
    max_retries: int = 3
    mark_sighted_on_hits: bool = True
    add_tags_to_observable: bool = True
    data_view_id: str = "logs-*"
    kibana: str = ""
    debug: bool = False

    def transport_options(self):
        # Set the same policy on the root client and its search-engine view.
        # A later .options(max_retries=0) would otherwise disable root retries.
        return {"request_timeout": self.request_timeout, "max_retries": self.max_retries,
                "retry_on_timeout": bool(self.max_retries)}

    @classmethod
    def from_values(cls, values):
        defaults = {d[0]: d[2] for d in OPTION_DEFINITIONS}
        defaults.update(values)
        values = defaults
        threshold = values["track_total_hits"]
        if isinstance(threshold, str) and threshold.lower() in ("true", "false"):
            threshold = threshold.lower() == "true"
        if not isinstance(threshold, bool):
            threshold = integer(threshold, "track_total_hits", minimum=0)
        mode = values["field_retrieval"]
        if mode not in ("source", "fields", "docvalues"):
            raise ValueError("field_retrieval must be source, fields, or docvalues")
        sort_order = values["sort_order"]
        if sort_order not in ("asc", "desc"):
            raise ValueError("sort_order must be asc (oldest first) or desc (newest first)")
        duration_seconds(values["pit_keep_alive"], "pit_keep_alive")
        server_seconds = duration_seconds(values["search_timeout"], "search_timeout")
        client_seconds = integer(values["request_timeout"], "request_timeout")
        if client_seconds <= server_seconds:
            raise ValueError("request_timeout must exceed search_timeout to allow response overhead")
        data_view_id = values["data_view_id"]
        if data_view_id is None or data_view_id == "":
            data_view_id = "logs-*"
        if (not isinstance(data_view_id, str) or not data_view_id.strip()
                or any(ord(c) < 32 or ord(c) == 127 for c in data_view_id)):
            raise ValueError("data_view_id must be a nonempty Kibana data-view ID")
        kibana = validate_kibana_url(values["kibana"])
        return cls(
            lookback_days=integer(values["lookback_days"], "lookback_days", 0),
            pit_threshold=integer(values["pit_threshold"], "pit_threshold", 1, 10000),
            pit_keep_alive=values["pit_keep_alive"], track_total_hits=threshold,
            field_retrieval=mode,
            include_report_fields=boolean(values["include_report_fields"], "include_report_fields"),
            return_fields=tuple(string_list(values["return_fields"], "return_fields", optional=True)),
            search_concurrency=integer(values["search_concurrency"], "search_concurrency", 1, 8),
            max_concurrent_shard_requests=integer(values["max_concurrent_shard_requests"], "max_concurrent_shard_requests"),
            sort_order=sort_order,
            search_timeout=values["search_timeout"], request_timeout=client_seconds,
            max_retries=integer(values["max_retries"], "max_retries", minimum=0),
            mark_sighted_on_hits=boolean(values["mark_sighted_on_hits"], "mark_sighted_on_hits"),
            add_tags_to_observable=boolean(values["add_tags_to_observable"], "add_tags_to_observable"),
            data_view_id=data_view_id, kibana=kibana,
            debug=boolean(values["debug"], "debug"),
        )


def base_field(field):
    return field.split("^", 1)[0]


def select_fields(configured, data_type):
    """Select configured groups once for Elasticsearch and the Kibana report."""
    names = query_field_group_names(data_type)
    if not isinstance(configured, dict):
        raise ValueError("Search field groups must be a configuration object")
    groups = default_field_groups()
    for name, default in groups.items():
        value = configured.get(name)
        groups[name] = string_list(default if value is None else value, name, optional=True)
    selected = list(dict.fromkeys(field for name in names for field in groups[name]))
    if not selected:
        raise ValueError("No configured search fields remain for observable type {}; configure {}".format(data_type, ", ".join(names)))
    return selected


def plain(response):
    value = getattr(response, "body", response)
    if not isinstance(value, dict):
        raise ValueError("Elasticsearch returned a non-object response")
    return value


def flat_values(document):
    """Flatten _source or fields, including arrays of objects and dotted keys."""
    output = {}
    def walk(value, prefix):
        if isinstance(value, dict):
            for key, child in value.items():
                walk(child, "{}.{}".format(prefix, key) if prefix else key)
        elif isinstance(value, list):
            for child in value:
                walk(child, prefix)
        elif value is not None and value != "":
            output.setdefault(prefix, []).append(value)
    if isinstance(document, dict):
        walk(document, "")
    return output


EVENT_TAG_FIELDS = {
    "data_stream": ("data_stream.type", "data_stream.dataset", "data_stream.namespace"),
    "observer": ("observer.product", "observer.vendor", "observer.version", "observer.id"),
}
IP_TAG_PROPERTIES = ("is_global", "is_link_local", "is_loopback", "is_multicast",
                     "is_private", "is_reserved", "is_unspecified")


def field_selected(name, patterns):
    """Match a requested leaf/wildcard, or a descendant of a literal parent."""
    return any(fnmatch.fnmatchcase(name, pattern) or name.startswith(pattern + ".") for pattern in patterns)


def expanded_tag_roots(fields):
    """Return full requested ECS objects through APIs that require leaf names."""
    return list(dict.fromkeys(field + ".*" if field in EVENT_TAG_FIELDS else field for field in fields))


def ip_observable_tags(data_type, value):
    """Classify an IP; true properties intentionally overlap. Callers cache reuse."""
    if data_type != "ip":
        return []
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ConfigurationError("The ip observable must be a valid IPv4 or IPv6 address") from error
    tags = ["ip:type:" + name[3:] for name in IP_TAG_PROPERTIES if getattr(address, name)]
    tags.append("ip:version:" + str(address.version))
    return sorted(tags)


def event_tags(hits, return_fields):
    """Collect only opted-in supported tags from final retained evidence."""
    tags = set()
    observer_fields = [field for field in EVENT_TAG_FIELDS["observer"] if field_selected(field, return_fields)]
    data_stream_fields = EVENT_TAG_FIELDS["data_stream"]
    include_stream = all(field_selected(field, return_fields) for field in data_stream_fields)
    for hit in hits:
        fields = hit.get("fields", {})
        for field in observer_fields:
            values = fields.get(field, [])
            for value in values if isinstance(values, list) else [values]:
                if isinstance(value, str) and value.strip():
                    tags.add(field + ":" + value.strip())
        if include_stream and not hit.get("_data_stream_ambiguous", False):
            components = []
            for field in data_stream_fields:
                values = fields.get(field, [])
                values = values if isinstance(values, list) else [values]
                # An array of distinct values cannot identify one stream. Do
                # not create a cartesian product or borrow from another hit.
                distinct = {value.strip() for value in values if isinstance(value, str) and value.strip()}
                if len(distinct) != 1 or any(not isinstance(value, str) or not value.strip() for value in values):
                    break
                components.append(next(iter(distinct)))
            if len(components) == 3:
                tags.add("data_stream:" + "-".join(components))
    return sorted(tags)


def parse_timestamp(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(value / 1000.0, timezone.utc)
    if not isinstance(value, str):
        raise ValueError("timestamp is missing or has an unsupported type")
    if re.fullmatch(r"-?[0-9]{11,}", value):
        return datetime.fromtimestamp(int(value) / 1000.0, timezone.utc)
    parsed = dateutil.parser.isoparse(value)
    return (parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed).astimezone(timezone.utc)


def parse_timestamp_for_sort(value):
    """Preserve date_nanos chronology while retaining existing display dates."""
    stamp = parse_timestamp(value)
    if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"-?[0-9]{11,}", value)):
        return stamp, Decimal(str(value)) / 1000
    elapsed = stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
    fraction = re.search(r"[Tt ](?:[0-9]{2}:[0-9]{2}:[0-9]{2}|[0-9]{6})[.,]([0-9]+)", value)
    subseconds = Decimal("0." + fraction[1]) if fraction else Decimal(stamp.microsecond) / 1000000
    return stamp, Decimal(elapsed.days * 86400 + elapsed.seconds) + subseconds


def convert_hit(raw, selected_fields, extra_fields, endpoint_id, sort_order="desc", observable_type=None):
    if not isinstance(raw, dict) or not isinstance(raw.get("_index"), str) or not isinstance(raw.get("_id"), str):
        raise ValueError("Hit is missing its index or document identifier")
    values = flat_values(raw.get("_source"))
    values.update(flat_values(raw.get("fields")))
    for field in [base_field(v) for v in selected_fields] + list(extra_fields):
        if field.endswith(".keyword") and field not in values and field[:-8] in values:
            values[field] = values[field[:-8]]
    hit = {"hitindex": raw["_index"], "hitid": raw["_id"], "endpoint_id": endpoint_id}
    report_fields = REPORT_FIELD_MAP
    if observable_type == "ip":
        report_fields = {**report_fields, **IP_REPORT_FIELD_MAP}
    for label, path in report_fields.items():
        found = values.get(path, [])
        hit[label] = found if label in ("process_args", "dns_resolvedip") else (found[0] if len(found) == 1 else found or "")
    hit.update({"timestamp": "", "time": "", "_sort_time": float("inf") if sort_order == "asc" else float("-inf")})
    warning = None
    try:
        raw_sort = raw.get("sort")
        if isinstance(raw_sort, (list, tuple)) and raw_sort:
            # Elasticsearch supplies the effective sort value, including the
            # selected min/max for multi-valued dates and missing sentinels.
            stamp, sort_time = parse_timestamp_for_sort(raw_sort[0])
        else:
            stamps = []
            for value in values.get("@timestamp", []):
                try:
                    stamps.append(parse_timestamp_for_sort(value))
                except (ValueError, TypeError, OverflowError, OSError):
                    continue
            if not stamps:
                raise ValueError("timestamp is missing or invalid")
            stamp, sort_time = (min if sort_order == "asc" else max)(stamps, key=lambda item: item[1])
        hit.update(timestamp=utc_string(stamp), time=stamp.strftime("%m/%d/%Y %I:%M %p UTC"), _sort_time=sort_time)
    except (ValueError, TypeError, OverflowError, OSError):
        warning = "missing_or_invalid_timestamp"
    requested = [base_field(v) for v in selected_fields] + list(extra_fields)
    hit["fields"] = {k: v for k, v in values.items() if field_selected(k, requested)}
    # Flattening multiple objects loses component correlations. A sole object
    # is unambiguous; never recombine leaves from separate objects in an array.
    if any(isinstance(container, dict) and isinstance(container.get("data_stream"), list)
           and len(container["data_stream"]) != 1
           and any(isinstance(value, dict) for value in container["data_stream"])
           for container in (raw.get("_source"), raw.get("fields"))):
        hit["_data_stream_ambiguous"] = True
    return hit, warning


def safe_endpoint(endpoint):
    try:
        parsed = urlsplit(endpoint)
        return urlunsplit((parsed.scheme, parsed.netloc.rsplit("@", 1)[-1], parsed.path, "", ""))
    except ValueError:
        return "invalid_endpoint"


def redact(text, secrets=()):
    text = re.sub(r"(https?://)[^/@\s]+@", r"\1[redacted]@", str(text))
    for secret in sorted((s for s in secrets if isinstance(s, str) and s), key=len, reverse=True):
        text = text.replace(secret, "[redacted]")
    return text[:2000]


def redact_diagnostic(value, secrets=()):
    """Copy backend diagnostics while removing known credentials/PIT tokens."""
    if isinstance(value, dict):
        return {key: redact_diagnostic(child, secrets) for key, child in value.items()}
    if isinstance(value, list):
        return [redact_diagnostic(child, secrets) for child in value]
    return redact(value, secrets) if isinstance(value, str) else value


def redact_job_submission(submission, secrets=()):
    """Copy the original job without truncation, masking credential values."""
    credential_names = {"key", "keys", "apikey", "apikeys", "password", "passwords",
                        "passwd", "passphrase", "secret", "secrets", "token", "tokens",
                        "accesstoken", "refreshtoken", "idtoken", "authorization",
                        "proxyauthorization", "clientsecret", "privatekey", "authtoken",
                        "bearertoken", "sessiontoken", "cookie", "cookies"}

    def credential(name):
        normalized = re.sub(r"[^a-z0-9]", "", str(name).lower())
        return (normalized in credential_names
                or normalized.endswith(("apikey", "apikeys", "password", "passwords",
                                        "clientsecret", "privatekey")))

    known = {v for v in secrets if isinstance(v, str) and v}

    def collect(value, sensitive=False):
        if isinstance(value, dict):
            for name, child in value.items():
                collect(child, sensitive or credential(name))
        elif isinstance(value, (list, tuple)):
            for child in value:
                collect(child, sensitive)
        elif sensitive and isinstance(value, str) and value:
            known.add(value)

    collect(submission)
    known = sorted(known, key=len, reverse=True)

    def copy(value, sensitive=False):
        if isinstance(value, dict):
            return {name: copy(child, sensitive or credential(name)) for name, child in value.items()}
        if isinstance(value, (list, tuple)):
            return [copy(child, sensitive) for child in value]
        if sensitive:
            return value if value is None or value == "" else "[redacted]"
        if isinstance(value, str):
            value = re.sub(r"(?i)(https?://)[^/@\s]+@", r"\1[redacted]@", value)
            value = re.sub(
                r"(?i)([?&](?:api[_-]?key|(?:access|refresh|auth|bearer|session|id)[_-]?token|token|password|secret|key)=)[^&#\s]*",
                r"\1[redacted]", value)
            for secret in known:
                value = value.replace(secret, "[redacted]")
        return value

    return copy(submission)


def backend_reason(error):
    """Include actual shard/root causes without dumping the full response body."""
    reasons = []
    for value in backend_nodes(error):
        label = ": ".join(str(value[k]) for k in ("type", "reason") if value.get(k))
        if label and label not in reasons:
            reasons.append(label)
        if len(reasons) >= 10:
            break
    return "; ".join(reasons) or str(error)


def backend_nodes(value):
    """Walk only Elasticsearch's structured error/shard-cause envelopes."""
    if not isinstance(value, dict):
        candidates = [getattr(value, name, None) for name in ("body", "error", "info")]
    else:
        candidates = [value]
    pending = [(node, 0) for node in candidates if isinstance(node, dict)]
    seen = set()
    while pending and len(seen) < 100:
        node, depth = pending.pop()
        if not isinstance(node, dict) or depth > 12 or id(node) in seen:
            continue
        seen.add(id(node))
        yield node
        for key in ("error", "caused_by", "reason", "_shards"):
            child = node.get(key)
            if isinstance(child, dict):
                pending.append((child, depth + 1))
        for key in ("root_cause", "failed_shards", "failures"):
            children = node.get(key, [])
            if isinstance(children, list):
                pending.extend((child, depth + 1) for child in children if isinstance(child, dict))


def missing_pit_context(value):
    return any(node.get("type") == "search_context_missing_exception" for node in backend_nodes(value))


def result_window_failure(value):
    """Return (recognized, bound) only for a real backend result-window error."""
    for node in backend_nodes(value):
        reason = node.get("reason")
        if node.get("type") != "illegal_argument_exception" or not isinstance(reason, str):
            continue
        if "result window is too large" not in reason.lower():
            continue
        match = re.search(r"less than or equal to\s*:\s*\[([0-9]+)\]", reason, re.I)
        return True, int(match[1]) if match and int(match[1]) > 0 else None
    return False, None


def build_search_query(fields, value, bounds):
    filters = [{"multi_match": {"query": value, "fields": list(fields)}}]
    if bounds:
        filters.append({"range": {"@timestamp": {"gte": bounds[0], "lte": bounds[1]}}})
    return {"bool": {"filter": filters}}


class SearchEngine:
    def __init__(self, es, settings, selected_fields, value, size, bounds, endpoint_id, secrets=(), runtime=None,
                 observable_type=None):
        self.es = es.options(**settings.transport_options())
        self.settings, self.selected, self.value, self.size = settings, selected_fields, value, size
        self.bounds, self.endpoint_id, self.secrets = bounds, endpoint_id, secrets
        self.observable_type = observable_type
        self.runtime = runtime or EndpointRuntimeController(
            self.es, settings.search_concurrency, settings.max_concurrent_shard_requests,
            settings.pit_threshold, secrets=secrets)
        fields = ["@timestamp"] + [base_field(v) for v in selected_fields] + list(settings.return_fields)
        if settings.include_report_fields:
            fields += list(REPORT_FIELD_MAP.values())
            if observable_type == "ip":
                fields += list(IP_REPORT_FIELD_MAP.values())
        self.return_fields = list(dict.fromkeys(fields))

    def new_result(self, index):
        return {"endpoint_id": self.endpoint_id, "index_pattern": index,
                "status": "failed", "execution_complete": False, "reason": "Search did not run",
                "reason_codes": [], "errors": [], "warnings": [], "pages_completed": 0,
                "es_took_ms": 0, "wall_ms": 0, "shards": None, "total_matches": None,
                "returned_count": 0, "retrieval_complete": None, "results_truncated": None,
                "stop_reason": None, "field_retrieval": self.settings.field_retrieval,
                "requested_fields": self.return_fields[:], "hits": [],
                "method": "ordinary", "decision_reason": None,
                "probe": {"attempted": False, "hits": 0, "wall_ms": 0,
                          "es_took_ms": 0, "complete": False, "discarded": False},
                "pit": {"enabled": False, "keep_alive": self.settings.pit_keep_alive,
                        "opened": False, "closed": None, "restarts": 0,
                        "snapshot_restarted": False, "attempts": []}}

    def error(self, result, code, reason, error=None):
        status_code = getattr(error, "status_code", None)
        if status_code is None and error is not None:
            status_code = getattr(getattr(error, "meta", None), "status", None)
        result["errors"].append({"code": code, "reason": redact(
            reason, list(self.secrets) + result.get("_redact_values", [])), "http_status": status_code})
        result["reason_codes"].append(code)
        progress = bool(result["pages_completed"] or result["hits"])
        shards = result.get("shards")
        if (result["pages_completed"] == 1 and not result["hits"] and isinstance(shards, dict)
                and shards.get("successful") == 0 and shards.get("failed", 0) > 0):
            # Receiving an empty response from failed shards is not usable
            # progress. Earlier successful PIT pages still make it partial.
            progress = False
        result["status"] = "partial" if progress else "failed"
        result["execution_complete"] = False
        result["reason"] = result["errors"][-1]["reason"]
        result["retrieval_complete"] = False
        result["stop_reason"] = code

    def exception(self, result, stage, error):
        body = getattr(error, "body", None)
        backend = body.get("error", {}) if isinstance(body, dict) else {}
        error_type = backend.get("type", "") if isinstance(backend, dict) else ""
        message = backend_reason(backend) if backend else str(error)
        combined = "{} {} {}".format(type(error).__name__, error_type, message).lower()
        if stage in ("pit_search", "pit_open") and missing_pit_context(error):
            code = "pit_expired_or_missing"
        elif "timeout" in combined:
            code = "request_timeout"
        else:
            code = stage + "_failed"
        self.error(result, code, "{}: {}".format(stage, message), error)

    def query(self):
        return build_search_query(self.selected, self.value, self.bounds)

    def fetch_fields(self, index):
        if self.settings.field_retrieval != "docvalues":
            return expanded_tag_roots(self.return_fields) if self.settings.field_retrieval == "fields" else self.return_fields
        # Field caps preflight prevents silent loss of mapped text/nested fields.
        requested = expanded_tag_roots(self.return_fields)
        parents = {".".join(f.split(".")[:i]) for f in requested for i in range(1, len(f.split(".")))}
        caps = plain(self.es.field_caps(index=index, fields=list(dict.fromkeys(requested + sorted(parents)))))
        available = caps.get("fields", {})
        nested = {name for name, types in available.items() if "nested" in types}
        resolved, unsupported = [], []
        allowed = {"keyword", "constant_keyword", "wildcard", "ip", "date", "date_nanos", "boolean",
                   "byte", "short", "integer", "long", "unsigned_long", "half_float", "float", "double", "scaled_float", "version"}
        for name, types in available.items():
            if not field_selected(name, requested):
                continue
            mapped = {t: c for t, c in types.items() if t != "unmapped"}
            if not mapped:
                continue
            # Plain objects contain no scalar values or doc values of their
            # own. Their selected leaves are validated separately below.
            # Nested or conflicting object/leaf mappings must still fail.
            if set(mapped) == {"object"}:
                continue
            if any(name.startswith(p + ".") for p in nested) or any(
                t not in allowed or not c.get("aggregatable") or c.get("non_aggregatable_indices") for t, c in mapped.items()
            ):
                unsupported.append(name)
            else:
                resolved.append(name)
        if unsupported:
            raise ValueError("docvalues cannot return these fields without loss: {}. Use field_retrieval=source or fields, or request only docvalue-enabled leaves in return_fields".format(
                ", ".join(sorted(unsupported))))
        return sorted(resolved)

    def body(self, *, pit_id=None, after=None, page_size=None, first=True, fetch_fields=None):
        body = {"size": self.size if page_size is None else page_size,
                "query": self.query(), "timeout": self.settings.search_timeout,
                "track_total_hits": self.settings.track_total_hits if first else False,
                "sort": [{"@timestamp": {"order": self.settings.sort_order, "missing": "_last", "unmapped_type": "date",
                                          "format": "strict_date_optional_time_nanos", "numeric_type": "date_nanos"}}]}
        mode = self.settings.field_retrieval
        if mode == "source":
            # Standard keyword multi-fields do not have their own _source entry.
            parents = [f[:-8] for f in self.return_fields if f.endswith(".keyword")]
            body["_source"] = list(dict.fromkeys(self.return_fields + parents))
        elif mode == "fields":
            body.update({"_source": False, "fields": expanded_tag_roots(self.return_fields)})
        else:
            body.update({"_source": False, "docvalue_fields": fetch_fields or []})
        if pit_id is not None:
            body["pit"] = {"id": pit_id, "keep_alive": self.settings.pit_keep_alive}
            body["sort"].append({"_shard_doc": "asc"})
        if after is not None:
            body["search_after"] = after
        return body

    def consume(self, result, response, first=True):
        response = plain(response)
        if "error" in response:
            backend = response["error"]
            reason = backend_reason(backend)
            error_type = backend.get("type", "search_error") if isinstance(backend, dict) else "search_error"
            if result["pit"]["enabled"] and missing_pit_context(response):
                error_type = "pit_expired_or_missing"
            self.error(result, error_type, reason)
            result["errors"][-1]["http_status"] = response.get("status")
            return []
        container = response.get("hits", {})
        hits = container.get("hits") if isinstance(container, dict) else None
        if not isinstance(hits, list):
            raise ValueError("Search response contains no hit list")
        result["pages_completed"] += 1
        took = response.get("took", 0)
        result["es_took_ms"] += took if isinstance(took, (int, float)) else 0
        result["shards"] = redact_diagnostic(
            response.get("_shards"), list(self.secrets) + result.get("_redact_values", []))
        if first:
            total = container.get("total")
            if isinstance(total, dict) and total.get("relation") in ("eq", "gte") and isinstance(total.get("value"), int) and total["value"] >= 0:
                result["total_matches"] = {"value": total["value"], "relation": total["relation"]}
            elif total is not None or self.settings.track_total_hits is not False:
                self.error(result, "invalid_total_metadata", "Search response has missing or invalid total-hit metadata")
            if result["total_matches"] and result["total_matches"]["relation"] == "eq" and result["total_matches"]["value"] < len(hits):
                self.error(result, "inconsistent_hit_count", "Returned hits exceed Elasticsearch's exact match count")
        for raw in hits:
            try:
                hit, warning = convert_hit(raw, self.selected, self.settings.return_fields, self.endpoint_id,
                                           self.settings.sort_order, self.observable_type)
                hit["matched_index_patterns"] = [result["index_pattern"]]
                result["hits"].append(hit)
                if warning and warning not in result["warnings"]:
                    result["warnings"].append(warning)
            except (ValueError, TypeError) as error:
                self.error(result, "invalid_document", str(error))
        if response.get("timed_out") is not False:
            self.error(result, "server_timeout", "Search timed out or did not provide completion status")
        shards = response.get("_shards")
        if not isinstance(shards, dict) or shards.get("failed") != 0:
            if result["pit"]["enabled"] and missing_pit_context(response):
                self.error(result, "pit_expired_or_missing", backend_reason(response.get("_shards", {})))
            else:
                self.error(result, "shard_failure", "Search has failed shards or missing shard status")
        clusters = response.get("_clusters", {})
        if isinstance(clusters, dict) and any(clusters.get(k, 0) for k in ("failed", "partial", "running", "skipped")):
            self.error(result, "remote_cluster_incomplete", "Search omitted one or more remote clusters")
        if not result["errors"]:
            result.update(status="complete", execution_complete=True, reason="Search executed successfully")
        return hits

    def finish(self, result, exhausted=False):
        result["returned_count"] = len(result["hits"])
        if result["errors"]:
            result["retrieval_complete"] = False
            return
        total = result["total_matches"]
        returned = result["returned_count"]
        if exhausted and total and total["value"] > returned:
            self.error(result, "inconsistent_hit_count", "Search ended before its reported match count was retrieved")
            return
        if exhausted or (total and total["relation"] == "eq" and returned == total["value"]):
            result.update(retrieval_complete=True, results_truncated=False, stop_reason="exhausted")
            # Exhausting a stable PIT (or one complete short response) proves the count.
            result["observed_total"] = {"value": returned, "relation": "eq"}
        elif total and total["value"] > returned:
            result.update(retrieval_complete=False, results_truncated=True, stop_reason="result_limit")
        else:
            result.update(retrieval_complete=None, results_truncated=None, stop_reason="result_limit")
        if result["stop_reason"] == "result_limit":
            result["reason"] = "Search executed successfully; reached the configured size limit"

    def request(self, method, **kwargs):
        """Observe real request pressure without introducing a separate count."""
        self.runtime.before_request()
        with self.runtime.request_permit():
            if "max_concurrent_shard_requests" in kwargs:
                kwargs["max_concurrent_shard_requests"] = self.runtime.shard_requests
            began = perf_counter()
            try:
                response = plain(method(**kwargs))
            except Exception as error:
                self.runtime.observe(error=error, wall_ms=(perf_counter() - began) * 1000)
                raise
            self.runtime.observe(response=response, wall_ms=(perf_counter() - began) * 1000)
        return response

    def ordinary_search(self, index, requested=None, fetch_fields=None):
        """One normal response; its useful evidence doubles as the auto probe."""
        result = self.new_result(index)
        began = perf_counter()
        response, caught = None, None
        requested = self.size if requested is None else requested
        try:
            if fetch_fields is None:
                fetch_fields = self.fetch_fields(index)
            response = self.request(
                self.es.search, index=index,
                body=self.body(page_size=requested, fetch_fields=fetch_fields),
                allow_partial_search_results=True,
                max_concurrent_shard_requests=self.runtime.shard_requests)
            page = self.consume(result, response)
            self.finish(result, exhausted=not result["errors"] and len(page) < requested)
        except Exception as error:
            caught = error
            self.exception(result, "search", error)
            self.finish(result)
        result["wall_ms"] = round((perf_counter() - began) * 1000, 3)
        return result, response, caught

    @staticmethod
    def attempt_diagnostic(result, attempt):
        """Keep failed-attempt context without leaking PIT IDs or mixing hits."""
        return {"attempt": attempt, "status": result["status"],
                "reason_codes": result["reason_codes"][:],
                "errors": result["errors"][:], "warnings": result["warnings"][:],
                "pages_completed": result["pages_completed"],
                "returned_count": len(result["hits"]),
                "total_matches": result["total_matches"],
                "wall_ms": result["wall_ms"], "es_took_ms": result["es_took_ms"],
                "closed": result["pit"]["closed"]}

    def _pit_attempt(self, index, fetch_fields, page_limit):
        result = self.new_result(index)
        result.update(method="pit")
        # Attempt-local secrets must never be shared across concurrent patterns
        # or retained in public diagnostics.
        result["_redact_values"] = []
        result["pit"]["enabled"] = True
        started, pit_id = perf_counter(), None
        try:
            open_options = {"index": index, "keep_alive": self.settings.pit_keep_alive,
                            "allow_partial_search_results": False,
                            "max_concurrent_shard_requests": self.runtime.shard_requests}
            if self.bounds:
                open_options["index_filter"] = {"range": {"@timestamp": {"gte": self.bounds[0], "lte": self.bounds[1]}}}
            opened = self.request(self.es.open_point_in_time, **open_options)
            pit_id = opened.get("id")
            if not isinstance(pit_id, str) or not pit_id:
                pit_id = None
                raise ValueError("PIT open response has no identifier")
            result["pit"]["opened"] = True
            result["_redact_values"].append(pit_id)
            shards = opened.get("_shards", {})
            if not isinstance(shards, dict) or shards.get("failed", 0):
                raise ValueError("PIT could not open all requested shards")
            after, seen = None, set()
            while len(result["hits"]) < self.size:
                page_size = min(page_limit, self.runtime.page_size, self.size - len(result["hits"]))
                first = result["pages_completed"] == 0
                response = self.request(
                    self.es.search,
                    body=self.body(pit_id=pit_id, after=after, page_size=page_size,
                                   first=first, fetch_fields=fetch_fields),
                    allow_partial_search_results=True,
                    max_concurrent_shard_requests=self.runtime.shard_requests)
                # Cleanup always uses the latest identifier, including failed pages.
                refreshed = response.get("pit_id")
                if isinstance(refreshed, str) and refreshed:
                    result["_redact_values"] = [pit_id, refreshed]
                    pit_id = refreshed
                page = self.consume(result, response, first=first)
                if result["errors"]:
                    break
                ids = [(h.get("_index"), h.get("_id")) for h in page]
                if len(set(ids)) != len(ids) or any(k in seen for k in ids):
                    self.error(result, "pagination_duplicate", "PIT pagination returned a repeated document")
                    break
                seen.update(ids)
                if len(page) < page_size:
                    self.finish(result, exhausted=True)
                    break
                total = result["total_matches"]
                if total and total["relation"] == "eq" and len(result["hits"]) >= total["value"]:
                    self.finish(result, exhausted=True)
                    break
                if len(result["hits"]) >= self.size:
                    self.finish(result)
                    break
                cursor = page[-1].get("sort")
                if not isinstance(cursor, list) or len(cursor) < 2 or cursor == after:
                    self.error(result, "pagination_not_advancing", "PIT page has no valid advancing search_after cursor")
                    break
                after = cursor
        except Exception as error:
            self.exception(result, "pit_search" if result["pit"]["opened"] else "pit_open", error)
        finally:
            if pit_id:
                try:
                    # A cleanup failure must never initiate another search/restart.
                    closed = self.request(self.es.close_point_in_time, body={"id": pit_id})
                    result["pit"]["closed"] = closed.get("succeeded") is True
                    if not result["pit"]["closed"]:
                        result["pit"]["close_reason"] = "Elasticsearch did not confirm PIT cleanup"
                        result["warnings"].append("pit_cleanup_unconfirmed")
                except Exception as error:
                    result["pit"].update(closed=False, close_reason=redact(
                        str(error), list(self.secrets) + result["_redact_values"]))
                    result["warnings"].append("pit_cleanup_failed")
            result["wall_ms"] = round((perf_counter() - started) * 1000, 3)
        self.finish(result, exhausted=result.get("retrieval_complete") is True)
        result.pop("_redact_values", None)
        return result

    def pit_search(self, index, fetch_fields=None, page_limit=None):
        started = perf_counter()
        if fetch_fields is None:
            try:
                fetch_fields = self.fetch_fields(index)
            except Exception as error:
                result = self.new_result(index)
                result["method"], result["pit"]["enabled"] = "pit", True
                self.exception(result, "field_retrieval", error)
                result["wall_ms"] = round((perf_counter() - started) * 1000, 3)
                return result
        page_limit = min(page_limit or self.settings.pit_threshold, self.settings.pit_threshold)
        attempts = []
        for attempt in (1, 2):
            result = self._pit_attempt(index, fetch_fields, page_limit)
            attempts.append(self.attempt_diagnostic(result, attempt))
            if "pit_expired_or_missing" not in result["reason_codes"] or attempt == 2:
                break
            # Never transfer a cursor, hit or count into another PIT snapshot.
        result["pit"].update(restarts=len(attempts) - 1, attempts=attempts,
                             snapshot_restarted=len(attempts) > 1)
        if len(attempts) > 1:
            result["warnings"].append("pit_snapshot_restarted")
        result["wall_ms"] = round((perf_counter() - started) * 1000, 3)
        return result

    def search_pattern(self, index):
        began = perf_counter()
        is_probe = self.size > self.settings.pit_threshold
        requested = min(self.size, self.settings.pit_threshold + 1, 10000) if is_probe else self.size
        result, response, caught = self.ordinary_search(index, requested=requested)
        probe = {"attempted": is_probe, "hits": len(result["hits"]),
                 "wall_ms": result["wall_ms"] if is_probe else 0,
                 "es_took_ms": result["es_took_ms"] if is_probe else 0,
                 "complete": result["execution_complete"] if is_probe else False,
                 "discarded": False}
        recognized_window, window_limit = result_window_failure(caught if caught is not None else response)
        if recognized_window:
            probe.update(discarded=True, errors=result["errors"][:], result_window_limit=window_limit)
            result = self.pit_search(index, page_limit=window_limit)
            result.update(decision_reason="result_window_requires_pit",
                          decision_detail="The index result window rejected ordinary retrieval; a fresh PIT was used")
        elif result["errors"]:
            result.update(decision_reason="probe_incomplete" if is_probe else "requested_size_within_threshold",
                          decision_detail="The initial search failed or was incomplete; its short response cannot prove exhaustion")
        elif not is_probe:
            result.update(decision_reason="requested_size_within_threshold",
                          decision_detail="Requested evidence fits in one ordinary response")
        elif len(result["hits"]) < requested:
            result.update(decision_reason="probe_exhausted", decision_detail="The completed probe returned all matching evidence")
        elif result["total_matches"] and result["total_matches"]["relation"] == "eq" and result["total_matches"]["value"] == len(result["hits"]):
            result.update(decision_reason="probe_exact_total", decision_detail="The probe retrieved Elasticsearch's exact match total")
        elif len(result["hits"]) >= self.size:
            result.update(decision_reason="probe_reached_requested_size", decision_detail="The ordinary response reached the requested evidence limit")
        else:
            probe["discarded"] = True
            result = self.pit_search(index)
            result.update(decision_reason="probe_requires_pagination",
                          decision_detail="The completed probe indicated more evidence; retrieval restarted from page one in a fresh PIT")
        result["probe"] = probe
        result["wall_ms"] = round((perf_counter() - began) * 1000, 3)
        return result

    def search_patterns(self, indices):
        if not indices:
            return []
        self.runtime.initialize()
        output = [None] * len(indices)
        def worker(index):
            try:
                result = self.search_pattern(index)
            except Exception as error:
                result = self.new_result(index)
                self.exception(result, "search_worker", error)
            result["runtime"] = self.runtime.snapshot()
            return result
        # Replenish only to the current limit, so reductions affect queued work.
        with ThreadPoolExecutor(max_workers=min(self.settings.search_concurrency, len(indices))) as executor:
            futures, next_index = {}, 0
            while futures or next_index < len(indices):
                while next_index < len(indices) and len(futures) < self.runtime.concurrency:
                    futures[executor.submit(worker, indices[next_index])] = next_index
                    next_index += 1
                done, _ = wait(futures, return_when=FIRST_COMPLETED)
                for future in done:
                    position = futures.pop(future)
                    output[position] = future.result()
        return output


def rison(value):
    if value is None:
        return "!n"
    if isinstance(value, bool):
        return "!t" if value else "!f"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, dict):
        return "(" + ",".join(str(k) + ":" + rison(v) for k, v in value.items()) + ")"
    if isinstance(value, (list, tuple)):
        return "!(" + ",".join(rison(v) for v in value) + ")"
    return "'" + str(value).replace("!", "!!").replace("'", "!'") + "'"


def kibana_document_url(base_url, data_view_id, index, document_id):
    """Build one document-view link from a validated base and opaque IDs."""
    if not base_url or not index or not document_id:
        return ""
    return "{}/app/discover#/doc/{}/{}?id={}".format(
        base_url.rstrip("/"), quote(data_view_id, safe=""),
        quote(index, safe=""), quote(document_id, safe=""))


def kibana_query(fields, value, kibana, dashboard, bounds, sort_order="desc"):
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    query_fields = dict.fromkeys(base_field(field) for field in fields)
    query = " or ".join('{}:"{}"'.format(field, escaped) for field in query_fields)
    if not kibana:
        return query, ""
    state = {"query": {"language": "kuery", "query": query}}
    if dashboard:
        link = kibana.rstrip("/") + "/app/dashboards#/view/" + quote(str(dashboard), safe="")
    else:
        link = kibana.rstrip("/") + "/app/discover#/"
        state["sort"] = [["@timestamp", sort_order]]
    parts = ["_a=" + quote(rison(state), safe="")]
    if bounds:
        parts.append("_g=" + quote(rison({"time": {"from": bounds[0], "to": bounds[1]}}), safe=""))
    return query, link + "?" + "&".join(parts)


class ElasticsearchAnalyzer(Analyzer):
    def __init__(self):
        super().__init__()
        # Preserve what Cortex submitted, before local defaults and overrides.
        self.job_submission = deepcopy(self.get_param([], {}))
        names = ("endpoints", "index", "keys", "users", "passwords", "dashboard",
                 "verifyssl", "cert_path", "size")
        self.analyzer_config = {name: self.get_param("config." + name, None) for name in names}
        for name, default in default_field_groups().items():
            value = self.get_param("config." + name, None)
            self.analyzer_config[name] = default if value is None else value
        for name, _, default, _ in SIGHTING_CONFIGURATION_DEFINITIONS:
            self.analyzer_config[name] = self.get_param("config." + name, default)
        # TheHive 4 injects this context for each invocation; it is not an
        # observable ID or a static analyzer configuration parameter.
        self.thehive_case_reference = self.get_param("message", None)
        self.thehive_organisation = self.get_param("parameters.organisation", None)
        self.option_values = {}
        for definition in OPTION_DEFINITIONS:
            name, default = definition[0], definition[2]
            value = self.get_param("parameters." + name, None)
            self.option_values[name] = self.get_param("config." + name, default) if value is None else value
        self.data = self.get_param("data", None)

    def update_observable_state(self, report, settings):
        url = self.analyzer_config.get("thehive_url")
        key = self.analyzer_config.get("thehive_api_key")
        case_reference = getattr(self, "thehive_case_reference", None)
        organisation = getattr(self, "thehive_organisation", None)
        request_context = {
            "thehive_url": safe_endpoint(url) if isinstance(url, str) and url else None,
            "organisation": organisation,
            "organisation_source": "parameters.organisation" if organisation is not None else "api_key_default",
            "organisation_header": None,
            "organisation_resolution": {"status": "not_requested", "reason_codes": []},
        }
        debug = None
        if settings.debug:
            debug = report["debug"] = {
                "job_submission": redact_job_submission(getattr(self, "job_submission", {}), [key]),
                **redact_job_submission({name: request_context[name] for name in ("thehive_url", "organisation")}, [key]),
            }
        else:
            report.pop("debug", None)
        sighting = {"enabled": settings.mark_sighted_on_hits, "status": "skipped", "sighted": None, "reason_codes": []}
        tagging = {"enabled": settings.add_tags_to_observable, "status": "skipped", "reason_codes": [],
                   "method": "operations", "operation_type": "AddTagToArtifact",
                   "tags_requested": sorted(set(report["tags"])) if settings.add_tags_to_observable else [],
                   "tags_added": None, "applied": None}
        report["search"]["sighting"] = sighting
        report["search"]["tagging"] = tagging
        if not settings.mark_sighted_on_hits:
            sighting.update(reason_codes=["disabled"], reason="Automatic sighting updates are disabled")
        elif not report["hits"]:
            sighting.update(reason_codes=["no_hits"], reason="No matching evidence was returned; existing sighted state is unchanged")
        if not settings.add_tags_to_observable:
            tagging.update(reason_codes=["disabled"], reason="Automatic observable tag updates are disabled")
        elif not report["tags"]:
            tagging.update(reason_codes=["no_tags"], reason="No report tags were generated")
        else:
            tagging.update(status="requested", reason="Requested {} tag operations; TheHive applies them after receiving this report. Application is not yet confirmed.".format(len(tagging["tags_requested"])))
        mark_sighted = settings.mark_sighted_on_hits and bool(report["hits"])
        if not mark_sighted:
            return
        if not url or not key:
            sighting.update(reason_codes=["not_configured"], reason="TheHive URL and API key are required for sighting updates")
            return
        if not case_reference:
            sighting.update(reason_codes=["missing_case_context"], reason="TheHive case context is missing from input.message; sighting update skipped")
            return
        try:
            if organisation is not None:
                request_context.update(organisation=organisation, organisation_header=organisation,
                                       organisation_resolution={"status": "provided", "reason_codes": []})
            arguments = dict(
                base_url=url, api_key=key, case_reference=case_reference,
                data_type=self.data_type, data=self.data,
                organisation=organisation, request_context=request_context,
                request_timeout=30,
                verify_ssl=boolean(self.analyzer_config.get("thehive_verifyssl", True), "thehive_verifyssl"),
                ca_file=self.analyzer_config.get("thehive_cert_path") or None,
            )
            sighting.update(mark_observable_sighted(**arguments))
            sighting["reason"] = "Observable was already sighted; no sighted change needed" if sighting["status"] == "already_sighted" else "Observable marked sighted from matching evidence"
        except Exception as error:
            if getattr(error, "code", None) == "invalid_organisation_context":
                request_context.update(organisation=None, organisation_header=None, organisation_resolution={
                    "status": "failed", "reason_codes": [error.code], "reason": redact(str(error), [key])})
            sighting.update(status="failed", reason_codes=[getattr(error, "code", "thehive_observable_update_failed")],
                            reason=redact(str(error), [key]), http_status=getattr(error, "http_status", None))
        finally:
            if debug is not None:
                debug.update(redact_job_submission(
                    {name: request_context[name] for name in ("thehive_url", "organisation")}, [key]))
                resolution = request_context.get("organisation_resolution", {})
                if resolution.get("status") == "failed":
                    debug["organisation_resolution"] = redact_job_submission(resolution, [key])

    def operations(self, raw):
        """Request additive tags for TheHive's originating job observable."""
        tagging = raw.get("search", {}).get("tagging", {})
        if tagging.get("enabled") is not True or tagging.get("status") != "requested":
            return []
        tags = string_list(tagging.get("tags_requested", []), "tags_requested", optional=True)
        # cortexutils 2.1.0 has no build_operation helper. The report protocol
        # accepts these dictionaries directly; no SDK helper is required.
        return [{"type": "AddTagToArtifact", "tag": tag} for tag in sorted(set(tags))]

    def report(self, full_report, ensure_ascii=False):
        """Include operations even with cortexutils 2.1.0's older report writer."""
        summary = {}
        try:
            summary = self.summary(full_report)
        except Exception:
            pass  # Preserve the SDK's optional-summary behavior.
        operations = []
        try:
            operations = self.operations(full_report)
        except Exception as error:
            # Keep the search evidence and expose failures the newer SDK hides.
            full_report.setdefault("search", {}).setdefault("tagging", {}).update(
                status="failed", reason_codes=["operation_generation_failed"],
                reason=redact(str(error)), tags_added=None, applied=None)
        return Worker.report(self, {
            "success": True, "summary": summary,
            "artifacts": self.artifacts(full_report),
            "operations": operations, "full": full_report,
        }, ensure_ascii=ensure_ascii)

    def summary(self, raw):
        search = raw.get("search", {})
        total = search.get("total_matches", {})
        value = total.get("value")
        relation = total.get("relation")
        count = "unknown"
        if value is not None and relation in ("eq", "gte"):
            count = (">=" if relation == "gte" else "") + str(value)
        status = search.get("status", "failed")
        status_level = "info"
        if status == "complete":
            status_level = "safe"
        elif status == "partial":
            status_level = "suspicious"
        elif status == "failed":
            status_level = "malicious"
        matches = len(raw.get("hits", []))
        # returned hits should remain suspicious even when the overall search is partial or failed
        matches_level = "info"
        if matches > 0:
            matches_level = "suspicious"
        elif status == "complete":
            matches_level = "safe"
        return {"taxonomies": [
            self.build_taxonomy(status_level, "ELK", "Search", status),
            self.build_taxonomy(matches_level, "ELK", "Hit(s)", "{} returned / {} matches".format(matches, count)),
        ]}

    def artifacts(self, raw):
        output, collected = [], {}
        classifications = getattr(self, "_ip_artifact_tag_cache", None)
        aliases = getattr(self, "_artifact_ip_aliases", None)
        if classifications is None:
            self._ip_artifact_tag_cache = classifications = {}
        if aliases is None:
            self._artifact_ip_aliases = aliases = {}
        original_kind = getattr(self, "data_type", None)
        original_value = getattr(self, "data", None)
        original_value = original_value.strip() if isinstance(original_value, str) else None
        if original_kind == "ip" and original_value:
            if original_value not in aliases:
                try:
                    aliases[original_value] = str(ipaddress.ip_address(original_value))
                except ValueError:
                    aliases[original_value] = None
            original_value = aliases[original_value]
        event_context = getattr(self, "_artifact_event_tags", {})
        return_fields = getattr(self, "_artifact_return_fields", None)
        if return_fields is None:
            return_fields = string_list(getattr(self, "option_values", {}).get("return_fields"),
                                        "return_fields", optional=True)
        for hit in raw.get("hits", []):
            hit_key = self._artifact_hit_key(hit)
            context_tags = event_context.get(hit_key)
            if context_tags is None:
                context_tags = event_tags([hit], return_fields)
            for kind, fields in (("domain", ("url_domain", "dns_question_name")),
                                 ("url", ("url_full",)), ("ip", ("source_ip", "destination_ip", "dns_resolvedip"))):
                for field in fields:
                    values = hit.get(field, [])
                    for value in values if isinstance(values, list) else [values]:
                        if not isinstance(value, str) or not value.strip():
                            continue
                        value = value.strip()
                        if kind == "ip":
                            if value not in aliases:
                                try:
                                    aliases[value] = str(ipaddress.ip_address(value))
                                except ValueError:
                                    aliases[value] = None
                            value = aliases[value]
                            if value is None:
                                continue
                        # TheHive already owns the analyzed observable. Tag it
                        # through native operations rather than offering it for
                        # artifact creation/import a second time.
                        if kind == original_kind and value == original_value:
                            continue
                        if kind == "ip":
                            if value not in classifications:
                                classifications[value] = tuple(ip_observable_tags("ip", value))
                        key = (kind, value)
                        if key not in collected:
                            artifact = {"dataType": kind, "data": value, "message": kind + " from elastic",
                                        "tags": [], "tlp": CORTEX_TLP_RED}
                            collected[key] = (artifact, set())
                            output.append(artifact)
                        if kind == "ip":
                            collected[key][1].update(classifications[value])
                            collected[key][1].update(context_tags)
        for artifact, tags in collected.values():
            artifact["tags"] = sorted(tags)
        return output

    @staticmethod
    def _artifact_hit_key(hit):
        """Keep event context addressable after report serialization/copying."""
        identity = tuple(hit.get(name) for name in ("endpoint_id", "hitindex", "hitid"))
        if not all(isinstance(value, str) and value for value in identity):
            return ("object", id(hit))
        profile = hit.get("endpoint_profile")
        # Two configured profiles may use the same URL for different clusters
        # or access scopes. Do not combine their event-derived artifact tags.
        return (profile,) + identity if type(profile) is int and profile > 0 else identity

    def endpoints(self):
        configured = self.analyzer_config["endpoints"]
        if isinstance(configured, str):
            configured = [configured]
        if not isinstance(configured, list) or not configured:
            raise ValueError("endpoints must specify at least one endpoint")
        endpoint_hosts = [string_list(endpoint, "endpoint hosts") for endpoint in configured]
        credentials = []
        for name in ("keys", "users", "passwords"):
            values = self.analyzer_config[name]
            values = [] if values is None else values if isinstance(values, list) else [values]
            if len(values) > len(endpoint_hosts):
                raise ValueError("{} has more entries than endpoints".format(name))
            credentials.append(values + [None] * (len(endpoint_hosts) - len(values)))
        profiles = [(hosts, credentials[0][n], credentials[1][n], credentials[2][n]) for n, hosts in enumerate(endpoint_hosts)]
        for hosts, key, user, password in profiles:
            for host in hosts:
                parsed = urlsplit(host)
                if parsed.scheme not in ("http", "https") or not parsed.hostname:
                    raise ConfigurationError("Each endpoint must be a valid http:// or https:// URL")
                # Accessing port also validates malformed/out-of-range port values.
                _ = parsed.port
            valid_key = key is None or isinstance(key, str) or (
                isinstance(key, (list, tuple)) and len(key) == 2 and all(isinstance(v, str) and v for v in key))
            if not valid_key:
                raise ConfigurationError("Each API key must be an encoded string or an ID/key pair")
            if user is not None and not isinstance(user, str):
                raise ConfigurationError("Each user must be a string")
            if password is not None and not isinstance(password, str):
                raise ConfigurationError("Each password must be a string")
            if user and not key and password is None:
                raise ConfigurationError("A password is required when a user is configured")
        return profiles

    def run(self):
        super().run()
        self._ip_artifact_tag_cache = {}
        self._artifact_ip_aliases = {}
        self._artifact_event_tags = {}
        self._artifact_return_fields = ()
        started, began = datetime.now(timezone.utc), perf_counter()
        report = {"hits": [], "tags": [], "info": {"data": self.data, "dashboard": self.analyzer_config.get("dashboard"),
                  "query": "", "querystring": "", "hitcount": 0, "uniqueusers": [], "uniquedevices": [],
                  "userhitcount": 0, "devicehitcount": 0, "entity_count_scope": "returned_unique_documents",
                  "time_timezone": "UTC"}, "total": "unknown",
                  "search": {"status": "failed", "execution_complete": False, "failed": True,
                             "reason": "Search did not run", "reason_codes": [], "queries": [],
                             "endpoints": [], "started_at": utc_string(started)}}
        results, collected = [], {}
        configuration_validated = False
        configuration_secrets = []
        pending = [self.analyzer_config.get(name) for name in ("keys", "passwords", "thehive_api_key")]
        while pending:
            value = pending.pop()
            if isinstance(value, str):
                configuration_secrets.append(value)
            elif isinstance(value, (list, tuple)):
                pending.extend(value)
        try:
            require_python_version()
            major = int(ES_VERSION[0])
            if major < 8 or (major == 8 and int(ES_VERSION[1]) < 19):
                raise ValueError("This analyzer requires elasticsearch-py 8.19+ or 9.x matching the server major")
            settings = Settings.from_values(self.option_values)
            if not isinstance(self.data, str) or not self.data.strip():
                raise ValueError("data must be a nonempty observable string")
            observable_tags = ip_observable_tags(self.data_type, self.data)
            if self.data_type == "ip":
                canonical_ip = str(ipaddress.ip_address(self.data))
                self._ip_artifact_tag_cache[canonical_ip] = tuple(observable_tags)
                self._artifact_ip_aliases.update({self.data: canonical_ip, canonical_ip: canonical_ip})
            self._artifact_return_fields = settings.return_fields
            indices = string_list(self.analyzer_config["index"], "index")
            fields = select_fields(self.analyzer_config, self.data_type)
            size = integer(self.analyzer_config["size"], "size")
            bounds = (utc_string(started - timedelta(days=settings.lookback_days)), utc_string(started)) if settings.lookback_days else None
            report["info"]["querystring"], report["info"]["query"] = kibana_query(
                fields, self.data, settings.kibana, self.analyzer_config["dashboard"], bounds, settings.sort_order)
            report["info"]["data_type"] = self.data_type
            kibana = {"base_url": settings.kibana, "observable_type": self.data_type, "query_fields": list(dict.fromkeys(base_field(f) for f in fields)),
                      "query": report["info"]["querystring"], "language": "kuery", "url": report["info"]["query"],
                      "target": ("dashboard" if self.analyzer_config["dashboard"] else "discover") if report["info"]["query"] else None,
                      "sort_order": settings.sort_order,
                      "sort_applied": bool(report["info"]["query"] and not self.analyzer_config["dashboard"]),
                      "time_window": {"from": bounds[0], "to": bounds[1]} if bounds else None,
                      "time_window_applied": bool(bounds and report["info"]["query"])}
            report["search"].update(
                observable_type=self.data_type, kibana=kibana,
                data_view_id=settings.data_view_id,
                query_dsl=build_search_query(fields, self.data, bounds),
                lookback_days=settings.lookback_days, time_window={"from": bounds[0], "to": bounds[1]} if bounds else None,
                time_scope="rolling_days" if bounds else "all_retained_data",
                query_fields=fields, query_field_groups=query_field_group_names(self.data_type),
                search_mode="auto", pit_threshold=settings.pit_threshold,
                pit_keep_alive=settings.pit_keep_alive,
                track_total_hits=settings.track_total_hits, field_retrieval=settings.field_retrieval,
                include_report_fields=settings.include_report_fields, size_per_index_pattern=size,
                search_concurrency=settings.search_concurrency,
                max_concurrent_shard_requests=settings.max_concurrent_shard_requests,
                sort_order=settings.sort_order, sort_field="@timestamp",
                sort_label="Oldest first" if settings.sort_order == "asc" else "Newest first",
                kibana_time_window_applied=bool(bounds and report["info"]["query"]),
                search_timeout=settings.search_timeout, **settings.transport_options(),
                analyzer_revision=ANALYZER_REVISION, client_version=".".join(str(v) for v in ES_VERSION))
            verify = True if self.analyzer_config["verifyssl"] is None else boolean(self.analyzer_config["verifyssl"], "verifyssl")
            endpoints = self.endpoints()
            configuration_validated = True
            for ordinal, (hosts, key, user, password) in enumerate(endpoints, 1):
                endpoint_hosts = [safe_endpoint(host) for host in hosts]
                endpoint_id = ", ".join(endpoint_hosts)
                endpoint_record = {"endpoint_id": endpoint_id, "endpoint_profile": ordinal,
                                   "hosts": endpoint_hosts}
                report["search"]["endpoints"].append(endpoint_record)
                secrets = [key, password]
                if isinstance(key, (list, tuple)):
                    secrets.extend(key)
                client, engine = None, None
                try:
                    kwargs = {"hosts": hosts, "verify_certs": verify, **settings.transport_options(),
                              "http_compress": True,
                              "connections_per_node": settings.search_concurrency}
                    if self.analyzer_config["cert_path"]:
                        kwargs["ca_certs"] = self.analyzer_config["cert_path"]
                    if key:
                        kwargs["api_key"] = tuple(key) if isinstance(key, list) else key
                    elif user:
                        if password is None:
                            raise ValueError("A password is required when a user is configured")
                        kwargs["basic_auth"] = (user, password)
                    try:
                        client = Elasticsearch(**kwargs)
                    except (ValueError, TypeError, OSError) as error:
                        # Client setup is local (URL/auth/TLS/CA configuration),
                        # before any Elasticsearch search is sent.
                        raise ConfigurationError(str(error)) from error
                    engine = SearchEngine(client, settings, fields, self.data, size, bounds, endpoint_id, secrets,
                                          observable_type=self.data_type)
                    endpoint_results = engine.search_patterns(indices)
                except ConfigurationError:
                    raise
                except Exception as error:
                    endpoint_results = []
                    for index in indices:
                        # Use the normal record/error machinery even if client construction failed.
                        engine = SearchEngine.__new__(SearchEngine)
                        engine.settings, engine.endpoint_id, engine.secrets = settings, endpoint_id, secrets
                        engine.return_fields = []
                        result = engine.new_result(index)
                        engine.exception(result, "endpoint", error)
                        endpoint_results.append(result)
                finally:
                    if client is not None:
                        try:
                            client.close()
                        except Exception as error:
                            endpoint_record["close_warning"] = redact(str(error), secrets)
                for result in endpoint_results:
                    result["endpoint_profile"] = ordinal
                    for hit in result.pop("hits"):
                        hit["endpoint_profile"] = ordinal
                        identity = (ordinal, hit["hitindex"], hit["hitid"])
                        if identity in collected:
                            previous = collected[identity]
                            previous["matched_index_patterns"] = sorted(set(previous["matched_index_patterns"] + hit["matched_index_patterns"]))
                        else:
                            collected[identity] = hit
                    results.append(result)
                if engine is not None and hasattr(engine, "runtime"):
                    endpoint_record["runtime"] = engine.runtime.snapshot()
            statuses = [r["status"] for r in results]
            # A failed index-pattern search must not be downgraded by successful
            # searches elsewhere. Partial means incomplete execution without a
            # wholly failed search; evidence is retained for all three states.
            query_counts = {name: statuses.count(name) for name in ("complete", "partial", "failed")}
            if not statuses or query_counts["failed"] or any(s not in query_counts for s in statuses):
                status = "failed"
                reason = ("{} of {} index-pattern searches failed".format(query_counts["failed"], len(statuses))
                          if query_counts["failed"] else "Search returned an invalid status" if statuses
                          else "No index-pattern searches completed")
            elif query_counts["partial"]:
                status = "partial"
                reason = "{} of {} index-pattern searches returned incomplete results".format(query_counts["partial"], len(statuses))
            else:
                status, reason = "complete", "All requested searches executed successfully"
            reasons = sorted({code for r in results for code in r["reason_codes"]})
            retrieval = [r["retrieval_complete"] for r in results]
            retrieval_complete = False if any(v is False for v in retrieval) else (True if retrieval and all(v is True for v in retrieval) else None)
            truncated = [r["results_truncated"] for r in results]
            results_truncated = True if any(v is True for v in truncated) else (False if truncated and all(v is False for v in truncated) else None)
            counts = [r.get("observed_total") or r["total_matches"] for r in results]
            counts_known = bool(counts) and all(c is not None for c in counts)
            relation = "unknown" if not counts_known else "eq" if status == "complete" and all(c["relation"] == "eq" for c in counts) else "gte"
            value = sum(c["value"] for c in counts) if counts_known else None
            report["search"].update(
                status=status, execution_complete=status == "complete", failed=status == "failed",
                reason=reason,
                reason_codes=reasons, queries=results, retrieval_complete=retrieval_complete, results_truncated=results_truncated,
                methods_used=sorted({r["method"] for r in results}),
                query_counts=query_counts,
                total_matches={"value": value, "relation": relation, "complete": status == "complete",
                               "scope": "sum_per_index_pattern; overlapping patterns can count the same document more than once"})
            report["total"] = relation
        except Exception as error:
            prefix = "Invalid configuration" if not configuration_validated or isinstance(error, ConfigurationError) else "Unexpected analyzer error"
            self.error("{}: {}".format(prefix, redact(str(error), configuration_secrets)))
            return
        hits = sorted(collected.values(), key=lambda h: (h["_sort_time"], h["endpoint_profile"], h["hitindex"], h["hitid"]), reverse=settings.sort_order == "desc")
        for hit in hits:
            hit.pop("_sort_time", None)
            document_url = kibana_document_url(settings.kibana, settings.data_view_id,
                                               hit["hitindex"], hit["hitid"])
            if document_url:
                hit["kibana_document_url"] = document_url
        report["hits"] = hits
        # Preserve each hit's validated tag context before removing private
        # ambiguity flags. Artifact extraction runs later in cortexutils.report.
        self._artifact_event_tags = {self._artifact_hit_key(hit): tuple(event_tags([hit], settings.return_fields))
                                     for hit in hits}
        report["tags"] = sorted(set(observable_tags).union(*self._artifact_event_tags.values()))
        for hit in hits:
            hit.pop("_data_stream_ambiguous", None)
        users, devices = set(), set()
        for hit in hits:
            for names, target in ((("user_name", "source_user_name"), users), (("host_name",), devices)):
                for name in names:
                    values = hit.get(name, [])
                    target.update(v.strip() for v in (values if isinstance(values, list) else [values]) if isinstance(v, str) and v.strip())
        report["info"].update(hitcount=len(hits), uniqueusers=sorted(users), uniquedevices=sorted(devices),
                              userhitcount=len(users), devicehitcount=len(devices),
                              duplicate_documents_removed=sum(r["returned_count"] for r in results) - len(hits))
        self.update_observable_state(report, settings)
        report["search"].update(completed_at=utc_string(datetime.now(timezone.utc)),
                                duration_ms=round((perf_counter() - began) * 1000, 3))
        # One diagnostic report for every endpoint; search failures are explicit in it.
        self.report(report)


if __name__ == "__main__":
    if sys.argv[1:] == ["--print-configuration-items"]:
        print(json.dumps(configuration_items(), indent=2))
    else:
        ElasticsearchAnalyzer().run()
