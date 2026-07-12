# IceMail Forwarding Manager Streamlit App

A local Streamlit UI for bulk IceMail domain forwarding operations.

## Features

1. Password gate before tool access
2. CSV upload and delimiter handling
3. Auto-detect email/domain column
4. Add forwarding or remove forwarding
5. CSV forwarding URL column or one shared forwarding URL
6. Fast uploaded-domain ID lookup in batches of 100
7. Domain ID cache reuse
8. Fresh full IceMail domain fetch when needed
9. Rate-limit-safe API execution
10. Preview before live execution
11. Downloadable full report, issues report, and summary JSON

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

Choose the domain ID source that matches the job:

1. Use **Fast lookup uploaded domains** for most CSVs. It resolves only the uploaded domains through the lookup API in batches of 100 and avoids downloading the whole workspace inventory.
2. Use domain cache for repeat runs on the same domain inventory.
3. Fetch the full domain list when you imported or bought new domains, moved domains between workspaces, your cache is older than your operational tolerance, or you see too many `not_found_in_icemail` results.

## Note

The app defaults to the `curl` HTTP engine because earlier Python `urllib` requests were blocked by Cloudflare browser signature checks.

The live operation button requires typing `CONFIRM`.
