# IceMail Forwarding Manager Streamlit App

A local Streamlit UI for bulk IceMail domain forwarding operations.

## Features

1. Password gate before tool access
2. CSV upload and delimiter handling
3. Auto-detect email/domain column
4. Add forwarding or remove forwarding
5. CSV forwarding URL column or one shared forwarding URL
6. Domain ID cache reuse
7. Fresh IceMail domain fetch when needed
8. Rate-limit-safe API execution
9. Preview before live execution
10. Downloadable full report, issues report, and summary JSON

## Install

```bash
cd icemail_streamlit_app
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configure password

```bash
mkdir -p .streamlit
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
```

Edit `.streamlit/secrets.toml`:

```toml
app_password = "your-local-password"
icemail_api_key = "your-icemail-api-key"
```

You can leave `icemail_api_key` blank and enter it in the sidebar.

## Run

```bash
streamlit run app.py
```

Or:

```bash
./run.sh
```

## Operational rule

Use domain cache for repeat runs on the same domain inventory.

Fetch fresh when:

1. You imported or bought new domains
2. You moved domains between workspaces
3. Your cache is older than your operational tolerance
4. You see too many `not_found_in_icemail` results

## Note

The app defaults to the `curl` HTTP engine because earlier Python `urllib` requests were blocked by Cloudflare browser signature checks.

The live operation button requires typing `CONFIRM`.
