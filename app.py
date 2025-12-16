import os
import json
import time
import io
from urllib.parse import urlencode

import streamlit as st
import pandas as pd
import requests

# --- CONFIG FROM STREAMLIT SECRETS / ENV ---
CLIENT_ID = st.secrets.get("AA_CLIENT_ID", os.getenv("AA_CLIENT_ID"))
CLIENT_SECRET = st.secrets.get("AA_CLIENT_SECRET", os.getenv("AA_CLIENT_SECRET"))
COMPANY_ID = st.secrets.get("AA_COMPANY_ID", os.getenv("AA_COMPANY_ID"))
REDIRECT_URI = st.secrets.get("AA_REDIRECT_URI", os.getenv("AA_REDIRECT_URI"))

if not CLIENT_ID or not CLIENT_SECRET or not COMPANY_ID or not REDIRECT_URI:
    st.error(
        "Missing required configuration for OAuth "
        "(AA_CLIENT_ID, AA_CLIENT_SECRET, AA_COMPANY_ID, AA_REDIRECT_URI)."
    )
    st.stop()

API_KEY = CLIENT_ID

IMS_AUTH_BASE = "https://ims-na1.adobelogin.com/ims/authorize/v2"
IMS_TOKEN_URL = "https://ims-na1.adobelogin.com/ims/token/v3"

# IMPORTANT:
# 1) These scopes must be enabled on the OAuth Web credential in Adobe Developer Console.
# 2) You can add read_apis,write_apis if you also enable them there.
SCOPES = (
    "additional_info.projectedProductContext,"
    "AdobeID,"
    "read_organizations,"
    "additional_info.job_function,"
    "openid"
    # If you've enabled Analytics API scopes in Dev Console, append:
    # ",read_apis,write_apis"
)


def build_auth_url(state: str) -> str:
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": SCOPES,
        "state": state,
    }
    return IMS_AUTH_BASE + "?" + urlencode(params)


def exchange_code_for_tokens(code: str) -> dict:
    """
    Exchange authorization code for access/refresh tokens via IMS.
    Logs the IMS error if something goes wrong.
    """
    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    resp = requests.post(IMS_TOKEN_URL, headers=headers, data=data)

    if not resp.ok:
        st.error(f"Token exchange failed: {resp.status_code} {resp.text}")
        resp.raise_for_status()

    return resp.json()


def refresh_access_token(refresh_token: str) -> dict:
    """
    Refresh the access token using a refresh token.
    (Not wired into main flow yet, but available if needed.)
    """
    data = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    resp = requests.post(IMS_TOKEN_URL, headers=headers, data=data)

    if not resp.ok:
        st.error(f"Refresh failed: {resp.status_code} {resp.text}")
        resp.raise_for_status()

    return resp.json()


def call_analytics_api(method: str, access_token: str, path: str):
    """
    Helper to call Analytics API with correct headers.
    method: 'GET' or 'DELETE'
    path: full path, e.g. /segments/{id} or /calculatedmetrics/{id}
    """
    headers = {
        "accept": "application/json",
        "Authorization": f"Bearer {access_token}",
        "x-api-key": API_KEY,
        "x-proxy-global-company-id": COMPANY_ID,
    }
    url = f"https://analytics.adobe.io/api/{COMPANY_ID}{path}"

    if method == "GET":
        return requests.get(url, headers=headers)
    elif method == "DELETE":
        return requests.delete(url, headers=headers)
    else:
        raise ValueError(f"Unsupported method: {method}")


def process_items(access_token: str, ids: list[str], item_type: str, dry_run: bool):
    """
    item_type: 'segments' or 'calculatedmetrics'
    dry_run: if True, only GET to check existence/permissions; no DELETE.
    Returns a list of log dicts.
    """
    logs = []
    total = len(ids)
    progress = st.progress(0)
    status_text = st.empty()

    for idx, item_id in enumerate(ids, start=1):
        if item_type == "segments":
            path = f"/segments/{item_id}"
        else:
            path = f"/calculatedmetrics/{item_id}"

        status_prefix = "Dry run" if dry_run else "Deleting"
        status_text.text(f"{status_prefix} ({idx}/{total}): {path}")

        if dry_run:
            # Check existence/permissions via GET
            response = call_analytics_api("GET", access_token, path)
        else:
            # Real delete via DELETE (with 429 retry)
            response = call_analytics_api("DELETE", access_token, path)
            while response.status_code == 429:
                time.sleep(0.5)
                response = call_analytics_api("DELETE", access_token, path)

        try:
            res = response.json()
        except ValueError:
            res = {}

        success = response.ok
        error_code = res.get("errorCode", "") if isinstance(res, dict) else ""
        error_desc = res.get("errorDescription", "") if isinstance(res, dict) else ""

        logs.append({
            "id": item_id,
            "type": item_type,
            "dry_run": dry_run,
            "method": "GET" if dry_run else "DELETE",
            "status_code": response.status_code,
            "success": success,
            "errorCode": error_code,
            "errorDescription": error_desc,
            "raw_response": json.dumps(res, ensure_ascii=False),
        })

        progress.progress(idx / total)

    status_text.text("Dry run complete." if dry_run else "Deletion complete.")
    return logs


# --- STREAMLIT APP ---

st.set_page_config(page_title="Adobe Analytics Bulk Delete", layout="wide")
st.title("Adobe Analytics Bulk Delete (Segments & Calculated Metrics)")

# Session storage for tokens
if "access_token" not in st.session_state:
    st.session_state["access_token"] = None
if "refresh_token" not in st.session_state:
    st.session_state["refresh_token"] = None

# --- OAuth callback handling at ROOT using st.query_params ---

if "code" in st.query_params and st.session_state["access_token"] is None:
    code = st.query_params["code"]
    st.write("Processing OAuth callback at root...")
    try:
        tokens = exchange_code_for_tokens(code)
        st.session_state["access_token"] = tokens["access_token"]
        st.session_state["refresh_token"] = tokens.get("refresh_token")
        st.success("Authentication successful. You can now run deletions.")
        # Clear query params so we don't re-process the code on rerun
        st.query_params.clear()
    except Exception as e:
        st.error(f"Failed to exchange code for tokens: {e}")
        st.stop()


# --- Authentication section ---

# --- Authentication section ---

if st.session_state["access_token"] is None:
    st.info("You are not authenticated.")
    if st.button("Sign in with Adobe"):
        state = "streamlit-aa-bulk-delete"  # For production, consider randomizing for CSRF
        auth_url = build_auth_url(state)
        st.write("Redirecting to Adobe login...")
        st.markdown(
            f'<script>window.location.href = "{auth_url}";</script>',
            unsafe_allow_html=True,
        )
        st.stop()
    st.stop()
else:
    st.success("Authenticated with Adobe. Token is available for this session.")
    # If you see 401s later, you can wire in refresh_access_token() and retry logic here.


# --- Main tool UI (only if authenticated) ---

item_type = st.selectbox(
    "Type of component to process:",
    options=["Segments", "Calculated Metrics"],
)

dry_run = st.checkbox(
    "Dry run (preview only – no deletions)",
    value=True,
    help="When enabled, the tool will only check that IDs exist and are accessible, "
         "but will NOT delete anything.",
)

uploaded_file = st.file_uploader("Upload CSV with column 'ID'", type=["csv"])

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    if "ID" not in df.columns:
        st.error("CSV must contain a column named 'ID'.")
    else:
        st.write("Preview of IDs:")
        st.dataframe(df.head())

        action_label = "Run Dry Run" if dry_run else "Delete Now"
        if st.button(action_label):
            access_token = st.session_state["access_token"]

            ids = df["ID"].astype(str).tolist()
            logs = process_items(
                access_token,
                ids,
                item_type="segments" if item_type == "Segments" else "calculatedmetrics",
                dry_run=dry_run,
            )

            log_df = pd.DataFrame(logs)
            st.subheader("Results")
            st.dataframe(log_df)

            csv_buffer = io.StringIO()
            log_df.to_csv(csv_buffer, index=False)
            st.download_button(
                label="Download Log CSV",
                data=csv_buffer.getvalue(),
                file_name="bulkDeleteLog.csv",
                mime="text/csv",
            )
