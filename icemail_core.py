from __future__ import annotations

import csv
import io
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Sequence, Tuple


DEFAULT_BASE_URL = "https://app.icemail.ai/api/v1"
ALT_BASE_URL = "https://inbox.closelix.com/api/v1"
DEFAULT_HTTP_ENGINE = "curl"
DEFAULT_PYTHON_USER_AGENT = "IceMailForwardingManagerStreamlit/1.0"
MAX_DOMAIN_LIST_LIMIT = 50
DEFAULT_CACHE_MAX_AGE_HOURS = 24
DOMAIN_CACHE_GLOB = "icemail_domain_cache_*.csv"

EMAIL_HEADER_HINTS = {
    "email",
    "email address",
    "email_address",
    "from_email",
    "sender_email",
    "mailbox",
    "mailbox email",
    "account email",
    "inbox",
}

DOMAIN_HEADER_HINTS = {
    "domain",
    "domains",
    "root domain",
    "root_domain",
    "sender domain",
    "sender_domain",
    "website",
    "company domain",
    "company_domain",
}

FORWARDING_HEADER_HINTS = {
    "forwarding_url",
    "forwarding url",
    "forwarding",
    "redirect_url",
    "redirect url",
    "destination_url",
    "destination url",
    "target_url",
    "target url",
}

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


@dataclass
class DomainRecord:
    domain: str
    domain_id: str
    status: str = ""
    domain_forwarding: Optional[bool] = None
    domain_forwarding_url: str = ""
    raw: Optional[Dict[str, Any]] = None


@dataclass
class OperationTarget:
    input_value: str
    normalized_domain: str
    domain_id: Optional[str]
    forwarding_url: str = ""
    status: str = "pending"
    message: str = ""


class ApiError(Exception):
    def __init__(self, message: str, status_code: Optional[int] = None, payload: Optional[Any] = None):
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class SlidingWindowRateLimiter:
    """Sliding-window limiter for documented IceMail sustained limits."""

    def __init__(self, max_calls: int, period_seconds: float, min_interval_seconds: float):
        self.max_calls = int(max_calls)
        self.period_seconds = float(period_seconds)
        self.min_interval_seconds = float(min_interval_seconds)
        self.calls: Deque[float] = deque()
        self.last_call_at = 0.0

    def wait(self) -> Optional[float]:
        now = time.monotonic()

        while self.calls and now - self.calls[0] >= self.period_seconds:
            self.calls.popleft()

        total_wait = 0.0

        if self.calls and len(self.calls) >= self.max_calls:
            wait_for = self.period_seconds - (now - self.calls[0]) + 0.05
            if wait_for > 0:
                time.sleep(wait_for)
                total_wait += wait_for

        now = time.monotonic()
        elapsed_since_last = now - self.last_call_at
        if elapsed_since_last < self.min_interval_seconds:
            wait_for = self.min_interval_seconds - elapsed_since_last
            time.sleep(wait_for)
            total_wait += wait_for

        now = time.monotonic()
        self.calls.append(now)
        self.last_call_at = now

        return total_wait if total_wait > 0 else None


class IceMailClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        http_engine: str = DEFAULT_HTTP_ENGINE,
        user_agent: str = "",
        curl_path: str = "curl",
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.api_key = api_key.strip()
        self.base_url = base_url.rstrip("/")
        self.http_engine = (http_engine or DEFAULT_HTTP_ENGINE).strip().lower()
        self.user_agent = (user_agent or "").strip()
        self.curl_path = curl_path or "curl"
        self.progress_callback = progress_callback

        if self.http_engine not in {"python", "curl"}:
            raise ValueError("HTTP engine must be either 'python' or 'curl'.")

        self.domain_list_limiter = SlidingWindowRateLimiter(
            max_calls=30,
            period_seconds=60,
            min_interval_seconds=0.20,
        )
        self.forwarding_limiter = SlidingWindowRateLimiter(
            max_calls=10,
            period_seconds=60,
            min_interval_seconds=1.00,
        )

    def emit(self, event: Dict[str, Any]) -> None:
        if self.progress_callback:
            self.progress_callback(event)

    def build_url(self, path: str, query: Optional[Dict[str, Any]] = None) -> str:
        url = self.base_url + path
        if query:
            clean_query = {k: v for k, v in query.items() if v is not None}
            url += "?" + urllib.parse.urlencode(clean_query)
        return url

    def request_with_curl(
        self,
        method: str,
        path: str,
        query: Optional[Dict[str, Any]] = None,
        body: Optional[Dict[str, Any]] = None,
        rate_limiter: Optional[SlidingWindowRateLimiter] = None,
        max_retries: int = 5,
    ) -> Dict[str, Any]:
        method = method.upper()
        url = self.build_url(path, query)
        body_json = json.dumps(body) if body is not None else None
        attempt = 0
        status_marker = "__ICEMAIL_HTTP_STATUS__:"

        while True:
            attempt += 1

            if rate_limiter:
                waited = rate_limiter.wait()
                if waited:
                    self.emit({"type": "rate_limit_wait", "waited_seconds": waited})

            cmd = [
                self.curl_path,
                "-sS",
                "--http1.1",
                "--connect-timeout",
                "20",
                "--max-time",
                "120",
                "-X",
                method,
                url,
                "-H",
                f"x-api-key: {self.api_key}",
                "-H",
                "Accept: application/json",
                "-w",
                f"\n{status_marker}%{{http_code}}",
            ]

            if self.user_agent:
                cmd.extend(["-A", self.user_agent])

            if body_json is not None:
                cmd.extend(["-H", "Content-Type: application/json", "--data-raw", body_json])

            try:
                result = subprocess.run(
                    cmd,
                    text=True,
                    capture_output=True,
                    timeout=150,
                )
            except FileNotFoundError as e:
                raise ApiError(
                    f"curl executable was not found at '{self.curl_path}'. Install curl or switch HTTP engine to Python."
                ) from e
            except subprocess.TimeoutExpired as e:
                if attempt <= max_retries:
                    wait_for = min(60, 2 ** attempt)
                    self.emit({"type": "retry_wait", "reason": "curl_timeout", "waited_seconds": wait_for})
                    time.sleep(wait_for)
                    continue
                raise ApiError("curl request timed out after retries.") from e

            stdout = result.stdout or ""
            stderr = result.stderr or ""

            if result.returncode != 0:
                if attempt <= max_retries:
                    wait_for = min(60, 2 ** attempt)
                    self.emit(
                        {
                            "type": "retry_wait",
                            "reason": f"curl_exit_{result.returncode}",
                            "stderr": stderr.strip(),
                            "waited_seconds": wait_for,
                        }
                    )
                    time.sleep(wait_for)
                    continue
                raise ApiError(f"curl failed with exit code {result.returncode}: {stderr.strip()}")

            if status_marker not in stdout:
                raise ApiError(f"curl response did not include HTTP status marker. stderr: {stderr.strip()}")

            body_text, status_text = stdout.rsplit(status_marker, 1)
            body_text = body_text.strip()
            status_text = status_text.strip()

            try:
                status_code = int(status_text)
            except ValueError as e:
                raise ApiError(f"Could not parse HTTP status code from curl output: {status_text}") from e

            payload = safe_json_loads(body_text) if body_text else {}

            if 200 <= status_code < 300:
                if payload is None:
                    raise ApiError(f"Could not parse successful API JSON response: {body_text[:500]}")
                return payload

            retry_after = extract_retry_after_from_payload(payload)

            if status_code == 429 and attempt <= max_retries:
                wait_for = retry_after or 60
                self.emit({"type": "retry_wait", "reason": "rate_limit_429", "waited_seconds": wait_for})
                time.sleep(wait_for)
                continue

            if status_code in {500, 502, 503, 504} and attempt <= max_retries:
                wait_for = min(60, 2 ** attempt)
                self.emit({"type": "retry_wait", "reason": f"server_{status_code}", "waited_seconds": wait_for})
                time.sleep(wait_for)
                continue

            raise ApiError(
                message=f"API request failed: {method} {url} returned HTTP {status_code}",
                status_code=status_code,
                payload=payload or body_text,
            )

    def request(
        self,
        method: str,
        path: str,
        query: Optional[Dict[str, Any]] = None,
        body: Optional[Dict[str, Any]] = None,
        rate_limiter: Optional[SlidingWindowRateLimiter] = None,
        max_retries: int = 5,
    ) -> Dict[str, Any]:
        if self.http_engine == "curl":
            return self.request_with_curl(
                method=method,
                path=path,
                query=query,
                body=body,
                rate_limiter=rate_limiter,
                max_retries=max_retries,
            )

        method = method.upper()
        url = self.build_url(path, query)

        data = None
        headers = {
            "x-api-key": self.api_key,
            "Accept": "application/json",
            "User-Agent": self.user_agent or DEFAULT_PYTHON_USER_AGENT,
        }

        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        attempt = 0

        while True:
            attempt += 1

            if rate_limiter:
                waited = rate_limiter.wait()
                if waited:
                    self.emit({"type": "rate_limit_wait", "waited_seconds": waited})

            req = urllib.request.Request(url, data=data, headers=headers, method=method)

            try:
                with urllib.request.urlopen(req, timeout=60) as response:
                    raw = response.read().decode("utf-8")
                    if not raw.strip():
                        return {}
                    return json.loads(raw)

            except urllib.error.HTTPError as e:
                raw_error = e.read().decode("utf-8", errors="replace")
                payload = safe_json_loads(raw_error)
                retry_after = extract_retry_after_from_payload(payload)

                if e.code == 429 and attempt <= max_retries:
                    wait_for = retry_after or 60
                    self.emit({"type": "retry_wait", "reason": "rate_limit_429", "waited_seconds": wait_for})
                    time.sleep(wait_for)
                    continue

                if e.code in {500, 502, 503, 504} and attempt <= max_retries:
                    wait_for = min(60, 2 ** attempt)
                    self.emit({"type": "retry_wait", "reason": f"server_{e.code}", "waited_seconds": wait_for})
                    time.sleep(wait_for)
                    continue

                raise ApiError(
                    message=f"API request failed: {method} {url} returned HTTP {e.code}",
                    status_code=e.code,
                    payload=payload or raw_error,
                )

            except urllib.error.URLError as e:
                if attempt <= max_retries:
                    wait_for = min(60, 2 ** attempt)
                    self.emit({"type": "retry_wait", "reason": "network_error", "waited_seconds": wait_for})
                    time.sleep(wait_for)
                    continue
                raise ApiError(f"Network request failed after retries: {e}") from e

            except json.JSONDecodeError as e:
                raise ApiError(f"Could not parse API JSON response from {method} {url}: {e}") from e

    def fetch_all_domains(self, limit: int = MAX_DOMAIN_LIST_LIMIT) -> Dict[str, DomainRecord]:
        page = 1
        all_domains: Dict[str, DomainRecord] = {}
        total_count: Optional[int] = None
        limit = min(int(limit), MAX_DOMAIN_LIST_LIMIT)

        self.emit({"type": "fetch_start", "base_url": self.base_url, "http_engine": self.http_engine})

        while True:
            self.emit({"type": "fetch_page_start", "page": page, "fetched": len(all_domains), "total": total_count})
            payload = self.request(
                "GET",
                "/domain",
                query={"page": page, "limit": limit},
                rate_limiter=self.domain_list_limiter,
            )

            data = payload.get("data", {}) if isinstance(payload, dict) else {}
            domains = data.get("domains", []) or []
            total_count = data.get("total_count", total_count)

            if not domains:
                break

            for item in domains:
                normalized = normalize_domain(str(item.get("domain", "")))
                domain_id = str(item.get("domain_id", "")).strip()

                if not normalized or not domain_id:
                    continue

                all_domains[normalized] = DomainRecord(
                    domain=normalized,
                    domain_id=domain_id,
                    status=str(item.get("status", "")),
                    domain_forwarding=item.get("domain_forwarding"),
                    domain_forwarding_url=str(item.get("domain_forwarding_url", "") or ""),
                    raw=item,
                )

            self.emit({"type": "fetch_page_done", "page": page, "fetched": len(all_domains), "total": total_count})

            if total_count and len(all_domains) >= int(total_count):
                break

            if len(domains) < limit:
                break

            page += 1

        self.emit({"type": "fetch_done", "fetched": len(all_domains), "total": total_count})
        return all_domains

    def apply_forwarding(self, domain_ids: Sequence[str], forwarding_url: str) -> Dict[str, Any]:
        return self.request(
            "PUT",
            "/domain/forwarding",
            body={"domain_ids": list(domain_ids), "forwarding_url": forwarding_url},
            rate_limiter=self.forwarding_limiter,
        )

    def remove_forwarding(self, domain_ids: Sequence[str]) -> Dict[str, Any]:
        return self.request(
            "DELETE",
            "/domain/forwarding",
            body={"domain_ids": list(domain_ids)},
            rate_limiter=self.forwarding_limiter,
        )


def safe_json_loads(value: str) -> Optional[Any]:
    try:
        return json.loads(value)
    except Exception:
        return None


def extract_retry_after_from_payload(payload: Optional[Any]) -> Optional[int]:
    if isinstance(payload, dict):
        for key in ("retry_after", "retryAfter", "retry_after_seconds"):
            if key in payload:
                try:
                    return int(float(payload[key]))
                except Exception:
                    pass
    return None


def strip_wrapping_quotes(value: str) -> str:
    value = str(value or "").strip()
    while len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1].strip()
    return value


def clean_header(value: str) -> str:
    return (value or "").strip().replace("\ufeff", "")


def normalized_header(value: str) -> str:
    return re.sub(r"\s+", " ", clean_header(value).lower().replace("-", "_")).strip()


def normalize_domain(value: str) -> str:
    if value is None:
        return ""

    raw = str(value).strip().lower()
    if not raw:
        return ""

    raw = raw.strip(" \t\r\n,;\"'<>[](){}")
    raw = raw.replace("mailto:", "")

    if "@" in raw and not raw.startswith("http"):
        raw = raw.split("@")[-1]

    candidate_for_parse = raw
    if "://" not in candidate_for_parse and "/" in candidate_for_parse:
        candidate_for_parse = "https://" + candidate_for_parse

    parsed = urllib.parse.urlparse(candidate_for_parse)
    host = parsed.netloc or parsed.path

    if "@" in host:
        host = host.split("@")[-1]

    host = host.split(":")[0]
    host = host.split("/")[0]
    host = host.strip(".").strip()

    if host.startswith("www."):
        host = host[4:]

    if host.startswith("*."):
        host = host[2:]

    try:
        host = host.encode("idna").decode("ascii")
    except Exception:
        pass

    if DOMAIN_RE.match(host):
        return host

    return ""


def extract_domain_from_email(value: str) -> str:
    if not value:
        return ""

    raw = str(value).strip().lower()
    raw = raw.strip(" \t\r\n,;\"'<>[](){}")

    match = re.search(r"[A-Z0-9._%+\-]+@([A-Z0-9.\-]+\.[A-Z]{2,})", raw, flags=re.IGNORECASE)
    if match:
        return normalize_domain(match.group(1))

    return ""


def is_valid_http_url(value: str) -> bool:
    if not value:
        return False

    try:
        parsed = urllib.parse.urlparse(str(value).strip())
    except Exception:
        return False

    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def detect_csv_dialect(sample: str, delimiter: Optional[str] = None) -> csv.Dialect:
    if delimiter and delimiter != "Auto":
        delimiter = strip_wrapping_quotes(delimiter)
        if delimiter == "\\t" or delimiter.upper() == "TAB":
            delimiter = "\t"
        if len(delimiter) != 1:
            raise ValueError("Delimiter must be exactly one character. Use TAB for tab.")
        dialect = csv.excel
        dialect.delimiter = delimiter
        return dialect

    sample = sample or ""
    sample = sample.replace("\x00", "")

    try:
        sniffed = csv.Sniffer().sniff(sample, delimiters=[",", ";", "\t", "|"])
        sniffed_delimiter = getattr(sniffed, "delimiter", None)
        if isinstance(sniffed_delimiter, str) and len(sniffed_delimiter) == 1:
            return sniffed
    except Exception:
        pass

    lines = [line for line in sample.splitlines() if line.strip()][:25]
    best_delimiter = ","
    best_score = -1

    for candidate in [",", ";", "\t", "|"]:
        column_counts = []
        for line in lines:
            try:
                parsed = next(csv.reader([line], delimiter=candidate))
                column_counts.append(len(parsed))
            except Exception:
                continue

        if not column_counts:
            continue

        multi_col_count = sum(1 for count in column_counts if count > 1)
        consistency_bonus = 5 if len(set(column_counts[:10])) == 1 and column_counts[0] > 1 else 0
        score = (multi_col_count * 10) + consistency_bonus + max(column_counts)

        if score > best_score:
            best_score = score
            best_delimiter = candidate

    dialect = csv.excel
    dialect.delimiter = best_delimiter
    return dialect


def read_csv_bytes(file_bytes: bytes, delimiter: Optional[str] = None) -> Tuple[List[Dict[str, str]], List[str], str]:
    encodings_to_try = ["utf-8-sig", "utf-8", "latin-1"]
    last_error: Optional[Exception] = None

    for encoding in encodings_to_try:
        try:
            raw_text = file_bytes.decode(encoding)
            raw_text = raw_text.replace("\x00", "")

            sample = raw_text[:8192]
            dialect = detect_csv_dialect(sample, delimiter=delimiter)
            detected_delimiter = getattr(dialect, "delimiter", ",")

            if not isinstance(detected_delimiter, str) or len(detected_delimiter) != 1:
                dialect = csv.excel
                dialect.delimiter = ","
                detected_delimiter = ","

            reader = csv.DictReader(io.StringIO(raw_text), dialect=dialect)

            if not reader.fieldnames:
                raise ValueError("CSV has no header row.")

            headers = [clean_header(h) for h in reader.fieldnames if h is not None]
            if not headers:
                raise ValueError("CSV has no usable headers.")

            if len(headers) == 1:
                header = headers[0]
                likely_delimiters = [d for d in [",", ";", "\t", "|"] if d != detected_delimiter and d in header]
                if likely_delimiters:
                    readable = ["TAB" if d == "\t" else d for d in likely_delimiters]
                    raise ValueError(
                        f"CSV parsed as one column using delimiter '{render_delimiter(detected_delimiter)}', "
                        f"but header contains possible delimiter(s): {readable}. Select the correct delimiter manually."
                    )

            rows: List[Dict[str, str]] = []
            for row in reader:
                cleaned_row = {}
                for header in headers:
                    cleaned_row[header] = str(row.get(header, "") or "").strip()
                rows.append(cleaned_row)

            return rows, headers, detected_delimiter

        except UnicodeDecodeError as e:
            last_error = e
            continue
        except csv.Error as e:
            last_error = e
            continue

    raise ValueError(f"Could not read CSV using common encodings. Last error: {last_error}")


def render_delimiter(delimiter: str) -> str:
    return "TAB" if delimiter == "\t" else delimiter


def score_column_as_email(rows: Sequence[Dict[str, str]], header: str) -> float:
    nh = normalized_header(header)
    score = 0.0

    if nh in EMAIL_HEADER_HINTS:
        score += 5.0
    if "email" in nh or "mailbox" in nh or "inbox" in nh:
        score += 3.0
    if "forward" in nh or "redirect" in nh or "url" in nh:
        score -= 4.0

    values = [str(row.get(header, "")).strip() for row in rows[:500] if str(row.get(header, "")).strip()]
    if not values:
        return score - 10.0

    valid = sum(1 for v in values if extract_domain_from_email(v))
    score += 10.0 * (valid / max(1, len(values)))
    return score


def score_column_as_domain(rows: Sequence[Dict[str, str]], header: str) -> float:
    nh = normalized_header(header)
    score = 0.0

    if nh in DOMAIN_HEADER_HINTS:
        score += 5.0
    if "domain" in nh or "website" in nh:
        score += 3.0
    if "forward" in nh or "redirect" in nh:
        score -= 5.0

    values = [str(row.get(header, "")).strip() for row in rows[:500] if str(row.get(header, "")).strip()]
    if not values:
        return score - 10.0

    valid_domains = 0
    email_like = 0

    for v in values:
        if "@" in v and extract_domain_from_email(v):
            email_like += 1
        if normalize_domain(v):
            valid_domains += 1

    score += 10.0 * (valid_domains / max(1, len(values)))
    score -= 3.0 * (email_like / max(1, len(values)))
    return score


def detect_domain_or_email_column(rows: Sequence[Dict[str, str]], headers: Sequence[str]) -> Tuple[Optional[str], Optional[str], float]:
    candidates: List[Tuple[float, str, str]] = []

    for header in headers:
        candidates.append((score_column_as_email(rows, header), header, "email"))
        candidates.append((score_column_as_domain(rows, header), header, "domain"))

    candidates.sort(reverse=True, key=lambda x: x[0])

    if not candidates or candidates[0][0] < 2.0:
        return None, None, 0.0

    best_score, best_header, best_type = candidates[0]
    return best_header, best_type, best_score


def detect_forwarding_url_column(rows: Sequence[Dict[str, str]], headers: Sequence[str]) -> Optional[str]:
    candidates: List[Tuple[float, str]] = []

    for header in headers:
        nh = normalized_header(header)
        score = 0.0

        if nh in FORWARDING_HEADER_HINTS:
            score += 7.0
        if "forward" in nh:
            score += 4.0
        if "redirect" in nh or "destination" in nh or "target" in nh:
            score += 3.0
        if "url" in nh or "link" in nh:
            score += 2.0
        if "domain" in nh or "email" in nh:
            score -= 3.0

        values = [str(row.get(header, "")).strip() for row in rows[:500] if str(row.get(header, "")).strip()]
        if values:
            valid_urls = sum(1 for v in values if is_valid_http_url(v))
            score += 10.0 * (valid_urls / len(values))

        candidates.append((score, header))

    candidates.sort(reverse=True, key=lambda x: x[0])

    if candidates and candidates[0][0] >= 4.0:
        return candidates[0][1]

    return None


def extract_unique_domains_from_rows(
    rows: Sequence[Dict[str, str]],
    column: str,
    column_type: str,
) -> Tuple[List[Tuple[str, str]], List[OperationTarget]]:
    seen = set()
    unique_pairs: List[Tuple[str, str]] = []
    invalid_targets: List[OperationTarget] = []

    for row in rows:
        raw_value = str(row.get(column, "")).strip()

        if not raw_value:
            continue

        if column_type == "email":
            domain = extract_domain_from_email(raw_value)
        else:
            domain = normalize_domain(raw_value)

        if not domain:
            invalid_targets.append(
                OperationTarget(
                    input_value=raw_value,
                    normalized_domain="",
                    domain_id=None,
                    status="invalid_input",
                    message="Could not extract a valid domain from this value.",
                )
            )
            continue

        if domain in seen:
            continue

        seen.add(domain)
        unique_pairs.append((raw_value, domain))

    return unique_pairs, invalid_targets


def map_targets_to_icemail_domains(
    unique_pairs: Sequence[Tuple[str, str]],
    icemail_domains: Dict[str, DomainRecord],
) -> List[OperationTarget]:
    targets: List[OperationTarget] = []

    for input_value, domain in unique_pairs:
        record = icemail_domains.get(domain)
        if record:
            targets.append(
                OperationTarget(
                    input_value=input_value,
                    normalized_domain=domain,
                    domain_id=record.domain_id,
                    status="matched",
                    message="Domain found in IceMail.",
                )
            )
        else:
            targets.append(
                OperationTarget(
                    input_value=input_value,
                    normalized_domain=domain,
                    domain_id=None,
                    status="not_found_in_icemail",
                    message="Domain was not found in the IceMail workspace domain list.",
                )
            )

    return targets


def attach_forwarding_urls(
    targets: List[OperationTarget],
    rows: Sequence[Dict[str, str]],
    domain_column: str,
    column_type: str,
    forwarding_url_column: Optional[str],
    global_forwarding_url: Optional[str],
) -> None:
    if global_forwarding_url:
        if not is_valid_http_url(global_forwarding_url):
            raise ValueError(f"Global forwarding URL is invalid: {global_forwarding_url}")
        for target in targets:
            if target.status == "matched":
                target.forwarding_url = global_forwarding_url.strip()
        return

    if not forwarding_url_column:
        raise ValueError("No forwarding URL source was provided.")

    domain_to_url: Dict[str, str] = {}

    for row in rows:
        raw_value = str(row.get(domain_column, "")).strip()
        url_value = str(row.get(forwarding_url_column, "")).strip()

        if not raw_value or not url_value:
            continue

        if column_type == "email":
            domain = extract_domain_from_email(raw_value)
        else:
            domain = normalize_domain(raw_value)

        if domain and is_valid_http_url(url_value):
            domain_to_url[domain] = url_value

    for target in targets:
        if target.status != "matched":
            continue

        target.forwarding_url = domain_to_url.get(target.normalized_domain, "")
        if not target.forwarding_url:
            target.status = "skipped_missing_forwarding_url"
            target.message = "Skipped because no valid forwarding URL was provided for this domain."


def chunked(items: Sequence[Any], size: int) -> Iterable[Sequence[Any]]:
    size = max(1, int(size))
    for i in range(0, len(items), size):
        yield items[i : i + size]


def targets_to_dicts(targets: Sequence[OperationTarget]) -> List[Dict[str, str]]:
    return [
        {
            "input_value": target.input_value,
            "normalized_domain": target.normalized_domain,
            "domain_id": target.domain_id or "",
            "forwarding_url": target.forwarding_url,
            "status": target.status,
            "message": target.message,
        }
        for target in targets
    ]


def targets_to_csv_bytes(targets: Sequence[OperationTarget]) -> bytes:
    fieldnames = ["input_value", "normalized_domain", "domain_id", "forwarding_url", "status", "message"]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(targets_to_dicts(targets))
    return output.getvalue().encode("utf-8")


def domain_cache_to_csv_bytes(domains: Dict[str, DomainRecord]) -> bytes:
    fieldnames = ["domain", "domain_id", "status", "domain_forwarding", "domain_forwarding_url"]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for domain in sorted(domains):
        record = domains[domain]
        writer.writerow(
            {
                "domain": record.domain,
                "domain_id": record.domain_id,
                "status": record.status,
                "domain_forwarding": record.domain_forwarding,
                "domain_forwarding_url": record.domain_forwarding_url,
            }
        )
    return output.getvalue().encode("utf-8")


def write_domain_cache(path: Path, domains: Dict[str, DomainRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(domain_cache_to_csv_bytes(domains))


def load_domain_cache(path: Path) -> Dict[str, DomainRecord]:
    rows, headers, _ = read_csv_bytes(path.read_bytes(), delimiter=",")
    header_lookup = {normalized_header(h): h for h in headers}

    if "domain" not in header_lookup or "domain_id" not in header_lookup:
        raise ValueError("Domain cache CSV must contain domain and domain_id columns.")

    domain_header = header_lookup["domain"]
    id_header = header_lookup["domain_id"]
    status_header = header_lookup.get("status")
    forwarding_header = header_lookup.get("domain_forwarding")
    forwarding_url_header = header_lookup.get("domain_forwarding_url")

    domains: Dict[str, DomainRecord] = {}

    for row in rows:
        domain = normalize_domain(row.get(domain_header, ""))
        domain_id = str(row.get(id_header, "")).strip()
        if not domain or not domain_id:
            continue

        forwarding_raw = str(row.get(forwarding_header, "")).strip().lower() if forwarding_header else ""
        if forwarding_raw in {"true", "1", "yes"}:
            forwarding_value: Optional[bool] = True
        elif forwarding_raw in {"false", "0", "no"}:
            forwarding_value = False
        else:
            forwarding_value = None

        domains[domain] = DomainRecord(
            domain=domain,
            domain_id=domain_id,
            status=str(row.get(status_header, "")).strip() if status_header else "",
            domain_forwarding=forwarding_value,
            domain_forwarding_url=str(row.get(forwarding_url_header, "")).strip() if forwarding_url_header else "",
        )

    return domains


def cache_age_seconds(path: Path) -> float:
    return max(0.0, time.time() - path.stat().st_mtime)


def format_cache_age(seconds: float) -> str:
    seconds_int = int(round(seconds))
    if seconds_int < 60:
        return f"{seconds_int}s old"

    minutes, secs = divmod(seconds_int, 60)
    if minutes < 60:
        return f"{minutes}m {secs}s old"

    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours}h {minutes}m old"

    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h old"


def count_cache_rows_quick(path: Path) -> int:
    try:
        return len(load_domain_cache(path))
    except Exception:
        return 0


def find_domain_cache_files(output_dir: Path, max_age_hours: float) -> List[Tuple[Path, float, int]]:
    if not output_dir.exists():
        return []

    max_age_seconds = float(max_age_hours) * 3600
    candidates: List[Tuple[Path, float, int]] = []

    for path in output_dir.glob(DOMAIN_CACHE_GLOB):
        if not path.is_file():
            continue

        try:
            age = cache_age_seconds(path)
            if age <= max_age_seconds:
                row_count = count_cache_rows_quick(path)
                if row_count > 0:
                    candidates.append((path, age, row_count))
        except Exception:
            continue

    candidates.sort(key=lambda item: item[0].stat().st_mtime, reverse=True)
    return candidates


def execute_operation(
    client: IceMailClient,
    action: str,
    targets: List[OperationTarget],
    batch_size: int,
    progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> List[OperationTarget]:
    started_at = time.time()

    if action == "add":
        eligible = [t for t in targets if t.status == "matched" and t.domain_id and t.forwarding_url]
        grouped: Dict[str, List[OperationTarget]] = defaultdict(list)
        for target in eligible:
            grouped[target.forwarding_url].append(target)

        batches: List[Tuple[str, Sequence[OperationTarget]]] = []
        for forwarding_url, group in grouped.items():
            for batch in chunked(group, batch_size):
                batches.append((forwarding_url, batch))

        total_batches = len(batches)
        for batch_index, (forwarding_url, batch) in enumerate(batches, start=1):
            if progress_callback:
                progress_callback(
                    {
                        "type": "operation_batch_start",
                        "batch_index": batch_index,
                        "total_batches": total_batches,
                        "domains_in_batch": len(batch),
                        "forwarding_url": forwarding_url,
                    }
                )

            domain_ids = [str(t.domain_id) for t in batch if t.domain_id]

            try:
                response = client.apply_forwarding(domain_ids, forwarding_url)
                success = bool(response.get("success", True)) if isinstance(response, dict) else True
                message = str(response.get("message", "Forwarding applied.")) if isinstance(response, dict) else "Forwarding applied."

                for target in batch:
                    target.status = "success" if success else "failed"
                    target.message = message

            except ApiError as e:
                message = f"{e}"
                if e.payload:
                    message += f" | API payload: {e.payload}"

                for target in batch:
                    target.status = "failed"
                    target.message = message

            if progress_callback:
                progress_callback(
                    {
                        "type": "operation_batch_done",
                        "batch_index": batch_index,
                        "total_batches": total_batches,
                        "elapsed_seconds": round(time.time() - started_at, 2),
                    }
                )

        return targets

    if action == "remove":
        eligible = [t for t in targets if t.status == "matched" and t.domain_id]
        batches = list(chunked(eligible, batch_size))
        total_batches = len(batches)

        for batch_index, batch in enumerate(batches, start=1):
            if progress_callback:
                progress_callback(
                    {
                        "type": "operation_batch_start",
                        "batch_index": batch_index,
                        "total_batches": total_batches,
                        "domains_in_batch": len(batch),
                    }
                )

            domain_ids = [str(t.domain_id) for t in batch if t.domain_id]

            try:
                response = client.remove_forwarding(domain_ids)
                success = bool(response.get("success", True)) if isinstance(response, dict) else True
                message = str(response.get("message", "Forwarding removed.")) if isinstance(response, dict) else "Forwarding removed."

                for target in batch:
                    target.status = "success" if success else "failed"
                    target.message = message

            except ApiError as e:
                message = f"{e}"
                if e.payload:
                    message += f" | API payload: {e.payload}"

                for target in batch:
                    target.status = "failed"
                    target.message = message

            if progress_callback:
                progress_callback(
                    {
                        "type": "operation_batch_done",
                        "batch_index": batch_index,
                        "total_batches": total_batches,
                        "elapsed_seconds": round(time.time() - started_at, 2),
                    }
                )

        return targets

    raise ValueError("Action must be 'add' or 'remove'.")


def summarize_targets(targets: Sequence[OperationTarget]) -> Dict[str, int]:
    counts: Dict[str, int] = defaultdict(int)
    for target in targets:
        counts[target.status] += 1
    return dict(sorted(counts.items()))


def build_summary(
    action: str,
    dry_run: bool,
    base_url: str,
    domain_source: str,
    targets: Sequence[OperationTarget],
    started_at: datetime,
    ended_at: datetime,
) -> Dict[str, Any]:
    elapsed_seconds = round((ended_at - started_at).total_seconds(), 2)
    return {
        "started_at": started_at.isoformat(timespec="seconds"),
        "ended_at": ended_at.isoformat(timespec="seconds"),
        "elapsed_seconds": elapsed_seconds,
        "elapsed_human": format_duration(elapsed_seconds),
        "action": action,
        "dry_run": dry_run,
        "base_url": base_url,
        "domain_source": domain_source,
        "total_unique_targets": len(targets),
        "counts_by_status": summarize_targets(targets),
    }


def summary_to_json_bytes(summary: Dict[str, Any]) -> bytes:
    return json.dumps(summary, indent=2, ensure_ascii=False).encode("utf-8")


def format_duration(seconds: float) -> str:
    seconds_int = int(round(seconds))
    hours, remainder = divmod(seconds_int, 3600)
    minutes, secs = divmod(remainder, 60)

    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def describe_403(api_error: ApiError) -> str:
    cloudflare_1010 = (
        isinstance(api_error.payload, dict)
        and api_error.payload.get("cloudflare_error") is True
        and str(api_error.payload.get("error_code")) == "1010"
    )

    if cloudflare_1010:
        return (
            "Cloudflare blocked the HTTP client signature before the request reached IceMail. "
            "Use the curl HTTP engine, or ask IceMail/Closelix to allow authenticated /api/v1 requests."
        )

    return (
        "IceMail returned 403. Check API key, workspace, role permissions, selected base URL, and copied whitespace."
    )
