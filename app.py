from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import streamlit as st

from icemail_core import (
    ALT_BASE_URL,
    DEFAULT_BASE_URL,
    DEFAULT_CACHE_MAX_AGE_HOURS,
    ApiError,
    IceMailClient,
    OperationTarget,
    attach_forwarding_urls,
    build_summary,
    describe_403,
    detect_domain_or_email_column,
    detect_forwarding_url_column,
    execute_operation,
    extract_unique_domains_from_rows,
    find_domain_cache_files,
    format_cache_age,
    is_valid_http_url,
    load_domain_cache,
    map_targets_to_icemail_domains,
    read_csv_bytes,
    render_delimiter,
    summarize_targets,
    summary_to_json_bytes,
    targets_to_csv_bytes,
    targets_to_dicts,
    write_domain_cache,
)


APP_TITLE = "IceMail Forwarding Manager"
DEFAULT_OUTPUT_DIR = Path("icemail_forwarding_outputs")


st.set_page_config(
    page_title=APP_TITLE,
    page_icon="📨",
    layout="wide",
    initial_sidebar_state="expanded",
)


def get_secret_or_env(secret_name: str, env_name: str, default: str = "") -> str:
    try:
        if secret_name in st.secrets:
            value = str(st.secrets[secret_name])
            if value:
                return value
    except Exception:
        pass

    return os.getenv(env_name, default)


def check_password() -> bool:
    expected_password = get_secret_or_env("app_password", "ICEMAIL_APP_PASSWORD", "")
    expected_hash = get_secret_or_env("app_password_sha256", "ICEMAIL_APP_PASSWORD_SHA256", "")

    if not expected_password and not expected_hash:
        st.error("App password is not configured.")
        st.code(
            """# Option 1: .streamlit/secrets.toml
app_password = "change-this"

# Option 2: environment variable
export ICEMAIL_APP_PASSWORD="change-this"
""",
            language="toml",
        )
        st.stop()

    if st.session_state.get("authenticated"):
        return True

    st.title(APP_TITLE)
    st.caption("Protected operational tool. Enter the app password to continue.")

    with st.form("password_gate"):
        password = st.text_input("App password", type="password")
        submitted = st.form_submit_button("Unlock")

    if submitted:
        ok = False
        if expected_password:
            ok = hmac.compare_digest(password, expected_password)
        if expected_hash:
            supplied_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
            ok = ok or hmac.compare_digest(supplied_hash, expected_hash)

        if ok:
            st.session_state["authenticated"] = True
            st.rerun()

        st.error("Wrong password.")

    st.stop()


@st.cache_data(show_spinner=False)
def cached_parse_csv(file_bytes: bytes, delimiter: str) -> Tuple[List[Dict[str, str]], List[str], str]:
    normalized_delimiter = None if delimiter == "Auto" else delimiter
    return read_csv_bytes(file_bytes, delimiter=normalized_delimiter)


def to_dataframe(targets: List[OperationTarget]) -> pd.DataFrame:
    return pd.DataFrame(targets_to_dicts(targets))


def build_client(api_key: str, base_url: str, http_engine: str, curl_path: str, user_agent: str, event_box=None, progress_bar=None) -> IceMailClient:
    def progress_callback(event: Dict[str, Any]) -> None:
        if not event_box:
            return

        event_type = event.get("type")

        if event_type == "fetch_start":
            event_box.info(f"Fetching IceMail domain list using {event.get('http_engine')}...")
        elif event_type == "fetch_page_start":
            page = event.get("page")
            fetched = event.get("fetched") or 0
            total = event.get("total")
            if total and progress_bar:
                progress_bar.progress(min(0.95, fetched / max(1, int(total))))
            event_box.info(f"Fetching domain page {page}. Fetched {fetched}{' of ' + str(total) if total else ''}.")
        elif event_type == "fetch_page_done":
            fetched = event.get("fetched") or 0
            total = event.get("total")
            if total and progress_bar:
                progress_bar.progress(min(0.95, fetched / max(1, int(total))))
            event_box.info(f"Fetched {fetched}{' of ' + str(total) if total else ''} domains.")
        elif event_type == "fetch_done":
            if progress_bar:
                progress_bar.progress(1.0)
            event_box.success(f"Fetched {event.get('fetched')} domains.")
        elif event_type == "lookup_start":
            total = event.get("domains_to_lookup") or 0
            batches = event.get("total_batches") or 0
            event_box.info(f"Looking up {total} uploaded domains in {batches} batch(es) using {event.get('http_engine')}...")
        elif event_type == "lookup_batch_start":
            batch_index = int(event.get("batch_index") or 0)
            total_batches = int(event.get("total_batches") or 1)
            if progress_bar:
                progress_bar.progress(min(0.95, (batch_index - 1) / max(1, total_batches)))
            event_box.info(
                f"Looking up domain batch {batch_index}/{total_batches}. "
                f"Resolved {event.get('resolved') or 0} so far."
            )
        elif event_type == "lookup_batch_done":
            batch_index = int(event.get("batch_index") or 0)
            total_batches = int(event.get("total_batches") or 1)
            if progress_bar:
                progress_bar.progress(min(0.95, batch_index / max(1, total_batches)))
            event_box.info(
                f"Completed lookup batch {batch_index}/{total_batches}. "
                f"Resolved {event.get('resolved') or 0} domains."
            )
        elif event_type == "lookup_done":
            if progress_bar:
                progress_bar.progress(1.0)
            event_box.success(
                f"Resolved {event.get('resolved') or 0} of {event.get('domains_to_lookup') or 0} uploaded domains."
            )
        elif event_type == "rate_limit_wait":
            event_box.warning(f"Rate limit safety wait: {round(float(event.get('waited_seconds') or 0), 1)} seconds.")
        elif event_type == "retry_wait":
            event_box.warning(
                f"Retry wait: {round(float(event.get('waited_seconds') or 0), 1)} seconds. Reason: {event.get('reason')}"
            )

    return IceMailClient(
        api_key=api_key,
        base_url=base_url,
        http_engine=http_engine,
        user_agent=user_agent,
        curl_path=curl_path,
        progress_callback=progress_callback,
    )


def resolve_domains_for_preview(
    client: IceMailClient,
    unique_pairs: List[Tuple[str, str]],
    cache_mode: str,
) -> Tuple[Dict[str, Any], str]:
    if cache_mode != "Fast lookup uploaded domains":
        return client.fetch_all_domains(), "api:list_domains"

    lookup_domains = getattr(client, "lookup_domains", None)
    if callable(lookup_domains):
        return lookup_domains([domain for _, domain in unique_pairs]), "api:lookup_domains"

    st.warning(
        "Fast lookup is not available in this running app process yet. "
        "Falling back to a full domain list fetch for this preview; restart the app to enable fast lookup."
    )
    return client.fetch_all_domains(), "api:list_domains_fallback_missing_lookup"


def render_cache_selector(output_dir: Path, cache_max_age_hours: float) -> Tuple[str, Optional[Path]]:
    caches = find_domain_cache_files(output_dir, cache_max_age_hours)
    cache_labels = [
        f"{path.name} ({row_count} domains, {format_cache_age(age)})"
        for path, age, row_count in caches
    ]

    source_options = [
        "Fast lookup uploaded domains",
        "Fetch full domain list",
    ]
    if caches:
        source_options = ["Use most recent cache", "Choose cache"] + source_options
    else:
        st.info("No recent domain cache found. You can still use fast lookup or fetch the full domain list.")

    cache_mode = st.radio(
        "Domain ID source",
        source_options,
        index=0,
        help=(
            "Fast lookup resolves only uploaded domains in batches of 100. "
            "Cache is best for repeat runs. Full fetch is slower but refreshes the complete workspace cache."
        ),
    )

    if cache_mode == "Use most recent cache":
        path, age, row_count = caches[0]
        st.success(f"Selected cache: {path.name} ({row_count} domains, {format_cache_age(age)})")
        return cache_mode, path

    if cache_mode == "Choose cache":
        selected_label = st.selectbox("Choose domain cache", cache_labels)
        selected_index = cache_labels.index(selected_label)
        path, age, row_count = caches[selected_index]
        return cache_mode, path

    if cache_mode == "Fast lookup uploaded domains":
        st.info("Fast lookup resolves only the uploaded domains and does not create or refresh a full domain cache.")
    else:
        st.warning("Full fetch can take several minutes depending on workspace size and API limits.")

    return cache_mode, None


def download_section(targets: List[OperationTarget], summary: Dict[str, Any], prefix: str) -> None:
    report_bytes = targets_to_csv_bytes(targets)
    not_found = [
        target
        for target in targets
        if target.status in {"not_found_in_icemail", "invalid_input", "skipped_missing_forwarding_url", "failed"}
    ]

    col1, col2, col3 = st.columns(3)
    with col1:
        st.download_button(
            "Download full report CSV",
            data=report_bytes,
            file_name=f"{prefix}_full_report.csv",
            mime="text/csv",
        )
    with col2:
        st.download_button(
            "Download issues CSV",
            data=targets_to_csv_bytes(not_found),
            file_name=f"{prefix}_issues.csv",
            mime="text/csv",
        )
    with col3:
        st.download_button(
            "Download summary JSON",
            data=summary_to_json_bytes(summary),
            file_name=f"{prefix}_summary.json",
            mime="application/json",
        )


def main() -> None:
    check_password()

    st.title(APP_TITLE)
    st.caption("Bulk add or remove IceMail domain forwarding with preview, cache reuse, rate-limit-safe execution, and downloadable reports.")

    with st.sidebar:
        st.header("Settings")

        default_key = get_secret_or_env("icemail_api_key", "ICEMAIL_API_KEY", "")
        api_key = st.text_input("IceMail API key", value=default_key, type="password")

        base_options = [DEFAULT_BASE_URL, ALT_BASE_URL, "Custom"]
        base_choice = st.selectbox(
            "API base URL",
            base_options,
            index=base_options.index(ALT_BASE_URL),
        )
        if base_choice == "Custom":
            base_url = st.text_input("Custom base URL", value=ALT_BASE_URL)
        else:
            base_url = base_choice

        http_engine = st.selectbox("HTTP engine", ["curl", "python"], index=0)
        curl_path = st.text_input("curl path", value="curl", disabled=http_engine != "curl")
        user_agent = st.text_input("Optional User-Agent", value="")

        output_dir = Path(st.text_input("Output/cache folder", value=str(DEFAULT_OUTPUT_DIR))).expanduser()
        cache_max_age_hours = st.number_input(
            "Recent cache max age, hours",
            min_value=1.0,
            max_value=720.0,
            value=float(DEFAULT_CACHE_MAX_AGE_HOURS),
            step=1.0,
        )

        batch_size = st.number_input(
            "Batch size per forwarding request",
            min_value=1,
            max_value=500,
            value=25,
            step=5,
            help="Lower batches reduce API-side partial-update risk; requests are still rate-limited and verified after completion.",
        )
        verify_after = st.checkbox(
            "Verify mutations with a fresh IceMail fetch after execution",
            value=True,
            help="Recommended. After API success, refetches domains and marks any still-wrong forwarding URL as failed.",
        )
        verification_delay_seconds = st.number_input(
            "Seconds to wait before verification fetch",
            min_value=0.0,
            max_value=60.0,
            value=3.0,
            step=1.0,
            help="Small delay gives IceMail time to make forwarding changes visible before verification.",
        )

        st.divider()
        if st.button("Lock app"):
            st.session_state.clear()
            st.rerun()

    st.subheader("1. Upload CSV")

    uploaded_file = st.file_uploader(
        "Upload a CSV with an email/domain column. For add forwarding, include forwarding_url or enter one URL manually.",
        type=["csv", "txt"],
    )

    delimiter = st.selectbox("CSV delimiter", ["Auto", ",", ";", "TAB", "|"], index=0)

    if not uploaded_file:
        st.stop()

    try:
        file_bytes = uploaded_file.getvalue()
        rows, headers, detected_delimiter = cached_parse_csv(file_bytes, delimiter)
    except Exception as e:
        st.error(f"Could not parse CSV: {e}")
        st.stop()

    st.success(f"Loaded {len(rows)} rows and {len(headers)} columns. Delimiter used: {render_delimiter(detected_delimiter)}")

    if not rows:
        st.error("CSV has no data rows.")
        st.stop()

    with st.expander("CSV preview", expanded=False):
        st.dataframe(pd.DataFrame(rows).head(25), use_container_width=True)

    st.subheader("2. Choose operation and columns")

    action_label = st.radio("Operation", ["Add forwarding", "Remove forwarding"], horizontal=True)
    action = "add" if action_label == "Add forwarding" else "remove"

    detected_column, detected_type, detected_score = detect_domain_or_email_column(rows, headers)

    default_column_index = headers.index(detected_column) if detected_column in headers else 0
    domain_column = st.selectbox(
        "Email or domain column",
        headers,
        index=default_column_index,
        help=f"Auto-detected: {detected_column} ({detected_type})" if detected_column else "No confident auto-detection.",
    )

    type_options = ["email", "domain"]
    default_type_index = type_options.index(detected_type) if detected_type in type_options else 0
    column_type = st.radio("Selected column contains", type_options, index=default_type_index, horizontal=True)

    forwarding_url: Optional[str] = None
    forwarding_url_column: Optional[str] = None

    if action == "add":
        detected_forwarding_col = detect_forwarding_url_column(rows, headers)

        forwarding_source_options = ["Use CSV forwarding URL column", "Use one URL for all matched domains"]
        if not detected_forwarding_col:
            default_forwarding_source = 1
        else:
            default_forwarding_source = 0

        forwarding_source = st.radio(
            "Forwarding URL source",
            forwarding_source_options,
            index=default_forwarding_source,
            horizontal=True,
        )

        if forwarding_source == "Use CSV forwarding URL column":
            default_fwd_index = headers.index(detected_forwarding_col) if detected_forwarding_col in headers else 0
            forwarding_url_column = st.selectbox("Forwarding URL column", headers, index=default_fwd_index)
        else:
            forwarding_url = st.text_input("Forwarding URL to apply to all matched domains", placeholder="https://example.com")
            if forwarding_url and not is_valid_http_url(forwarding_url):
                st.error("Forwarding URL must be a full http or https URL.")

    unique_pairs, invalid_targets = extract_unique_domains_from_rows(rows, domain_column, column_type)

    c1, c2, c3 = st.columns(3)
    c1.metric("CSV rows", len(rows))
    c2.metric("Unique valid domains", len(unique_pairs))
    c3.metric("Invalid input values", len(invalid_targets))

    if not unique_pairs:
        st.error("No valid domains could be extracted from the selected column.")
        st.stop()

    st.subheader("3. Choose domain ID source")

    cache_mode, selected_cache_path = render_cache_selector(output_dir, cache_max_age_hours)

    st.subheader("4. Build preview")

    preview_disabled = not api_key or (action == "add" and forwarding_url is not None and not is_valid_http_url(forwarding_url))

    if not api_key:
        st.warning("Enter your IceMail API key in the sidebar.")

    build_preview = st.button("Build preview", type="primary", disabled=preview_disabled)

    if build_preview:
        started_at = datetime.now()

        try:
            output_dir.mkdir(parents=True, exist_ok=True)

            if selected_cache_path:
                domain_source = f"cache:{selected_cache_path}"
                icemail_domains = load_domain_cache(selected_cache_path)
                st.success(f"Loaded {len(icemail_domains)} IceMail domains from cache.")
            else:
                fetch_status = st.empty()
                fetch_progress = st.progress(0)
                client = build_client(api_key, base_url, http_engine, curl_path, user_agent, fetch_status, fetch_progress)

                icemail_domains, domain_source = resolve_domains_for_preview(client, unique_pairs, cache_mode)

                if domain_source.startswith("api:list_domains"):
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    cache_path = output_dir / f"icemail_domain_cache_{timestamp}.csv"
                    write_domain_cache(cache_path, icemail_domains)
                    st.success(f"Saved fresh domain cache: {cache_path}")

            targets = map_targets_to_icemail_domains(unique_pairs, icemail_domains)
            targets.extend(invalid_targets)

            if action == "add":
                attach_forwarding_urls(
                    targets=targets,
                    rows=rows,
                    domain_column=domain_column,
                    column_type=column_type,
                    forwarding_url_column=forwarding_url_column,
                    global_forwarding_url=forwarding_url,
                )

            ended_at = datetime.now()
            summary = build_summary(
                action=action,
                dry_run=True,
                base_url=base_url.rstrip("/"),
                domain_source=domain_source,
                targets=targets,
                started_at=started_at,
                ended_at=ended_at,
            )

            st.session_state["preview_targets"] = targets
            st.session_state["preview_summary"] = summary
            st.session_state["preview_config"] = {
                "action": action,
                "base_url": base_url,
                "http_engine": http_engine,
                "curl_path": curl_path,
                "user_agent": user_agent,
                "batch_size": int(batch_size),
                "verify_after": bool(verify_after),
                "verification_delay_seconds": float(verification_delay_seconds),
            }

        except ApiError as e:
            if e.status_code == 403:
                st.error(describe_403(e))
                st.json(e.payload)
            else:
                st.error(str(e))
                if e.payload:
                    st.json(e.payload)
        except Exception as e:
            st.error(str(e))

    targets = st.session_state.get("preview_targets")
    summary = st.session_state.get("preview_summary")

    if not targets or not summary:
        st.stop()

    st.subheader("5. Review preview")

    counts = summarize_targets(targets)
    metric_cols = st.columns(max(1, min(5, len(counts))))
    for idx, (status, count) in enumerate(counts.items()):
        metric_cols[idx % len(metric_cols)].metric(status, count)

    preview_df = to_dataframe(targets)
    st.dataframe(preview_df, use_container_width=True, height=360)

    timestamp_prefix = datetime.now().strftime("icemail_%Y%m%d_%H%M%S")
    download_section(targets, summary, f"{timestamp_prefix}_preview")

    matched_count = counts.get("matched", 0)
    skipped_count = counts.get("skipped_missing_forwarding_url", 0)
    not_found_count = counts.get("not_found_in_icemail", 0)
    invalid_count = counts.get("invalid_input", 0)

    st.subheader("6. Execute")

    st.warning(
        f"Ready to process {matched_count} matched domains. "
        f"Issues before execution: {not_found_count} not found, {invalid_count} invalid, {skipped_count} missing forwarding URL."
    )

    confirm_text = st.text_input("Type CONFIRM to enable live execution")
    execute_disabled = confirm_text != "CONFIRM" or matched_count == 0

    if st.button("Execute live IceMail operation", type="primary", disabled=execute_disabled):
        config = st.session_state["preview_config"]
        started_at = datetime.now()

        op_status = st.empty()
        op_progress = st.progress(0)

        def operation_progress(event: Dict[str, Any]) -> None:
            event_type = event.get("type")
            if event_type == "operation_batch_start":
                batch_index = int(event.get("batch_index") or 0)
                total_batches = int(event.get("total_batches") or 1)
                op_progress.progress(min(0.99, (batch_index - 1) / max(1, total_batches)))
                op_status.info(
                    f"Processing batch {batch_index}/{total_batches}, {event.get('domains_in_batch')} domains."
                )
            elif event_type == "operation_batch_done":
                batch_index = int(event.get("batch_index") or 0)
                total_batches = int(event.get("total_batches") or 1)
                op_progress.progress(min(1.0, batch_index / max(1, total_batches)))
                op_status.info(f"Completed batch {batch_index}/{total_batches}.")
            elif event_type == "rate_limit_wait":
                op_status.warning(f"Rate limit safety wait: {round(float(event.get('waited_seconds') or 0), 1)} seconds.")
            elif event_type == "verification_wait":
                op_status.info(f"Waiting {round(float(event.get('waited_seconds') or 0), 1)} seconds before verification fetch.")
            elif event_type == "verification_start":
                op_status.info(f"Verifying {event.get('domains_to_verify')} domains with a fresh IceMail fetch.")
            elif event_type == "verification_done":
                op_status.info(
                    f"Verification complete: {event.get('domains_verified')} verified, "
                    f"{event.get('domains_failed')} failed."
                )

        client = build_client(
            api_key=api_key,
            base_url=config["base_url"],
            http_engine=config["http_engine"],
            curl_path=config["curl_path"],
            user_agent=config["user_agent"],
        )
        client.progress_callback = operation_progress

        try:
            final_targets = execute_operation(
                client=client,
                action=config["action"],
                targets=targets,
                batch_size=int(config["batch_size"]),
                progress_callback=operation_progress,
                verify_after=bool(config.get("verify_after", True)),
                verification_delay_seconds=float(config.get("verification_delay_seconds", 3.0)),
            )
            ended_at = datetime.now()
            final_summary = build_summary(
                action=config["action"],
                dry_run=False,
                base_url=config["base_url"].rstrip("/"),
                domain_source=summary.get("domain_source", ""),
                targets=final_targets,
                started_at=started_at,
                ended_at=ended_at,
            )

            st.session_state["final_targets"] = final_targets
            st.session_state["final_summary"] = final_summary
            op_progress.progress(1.0)
            op_status.success("Live operation completed.")

        except ApiError as e:
            if e.status_code == 403:
                st.error(describe_403(e))
                st.json(e.payload)
            else:
                st.error(str(e))
                if e.payload:
                    st.json(e.payload)
        except Exception as e:
            st.error(str(e))

    final_targets = st.session_state.get("final_targets")
    final_summary = st.session_state.get("final_summary")

    if final_targets and final_summary:
        st.subheader("7. Final results")
        final_counts = summarize_targets(final_targets)
        final_cols = st.columns(max(1, min(5, len(final_counts))))
        for idx, (status, count) in enumerate(final_counts.items()):
            final_cols[idx % len(final_cols)].metric(status, count)

        st.dataframe(to_dataframe(final_targets), use_container_width=True, height=360)
        download_section(final_targets, final_summary, f"{timestamp_prefix}_final")


if __name__ == "__main__":
    main()
