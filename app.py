import os
import json
import time
import io
from urllib.parse import urlencode

import streamlit as st
import pandas as pd
import requests

# --- CONFIG FROM STREAMLIT SECRETS / ENV ---
# On Streamlit Cloud, you'll use st.secrets; locally, you can fallback to env vars.
CLIENT_ID = st.secrets.get("AA_CLIENT_ID", os.getenv("AA_CLIENT_ID"))
CLIENT_SECRET = st.secrets.get("AA_CLIENT_SECRET", os.getenv("AA_CLIENT_SECRET"))
COMPANY_ID = st.secrets.get("AA_COMPANY_ID", os.getenv("AA_COMPANY_ID"))
REDIRECT_URI = st.secrets.get("AA_REDIRECT_URI", os.getenv("AA_REDIRECT_URI"))

if not CLIENT_ID or not CLIENT_SECRET or not COMPANY_ID or not REDIRECT_URI:
    st.error("Missing required configuration for OAuth (CLIENT_ID/SECRET, COMPANY_ID, REDIRECT_URI).")
    st.stop()

API_KEY = CLIENT_ID

IMS_AUTH_BASE = "https://ims-na1.adobelogin.com/ims/authorize/v2"
IMS_TOKEN_URL = "https://ims-na1.adobelogin.com/ims/token/v3"
SCOPES = "additional_info.projectedProductContext, AdobeID, read_organizations, additional_info.job_function, openid"


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
    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    resp = requests.post(IMS_TOKEN_URL, headers=headers, data=data)
    resp.raise_for_status()
    return resp.json()


def refresh_access_token(refresh_token: str) -> dict:
    data = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    resp = requests.post(IMS_TOKEN_URL, headers=headers, data=data)
    resp.raise_for_status()
    return resp.json()


def delete_items(access_token: str, ids: list[str], item_type: str):
    """
    item_type: 'segments' or 'calculatedmetrics'
    Returns a list of log dicts.
    """
    headers = {
        "accept": "application/json",
        "Authorization": f"Bearer {access_token}",
        "x-api-key": API_KEY,
        "x-proxy-global-company-id": COMPANY_ID,
    }

    logs = []
    total = len(ids)
    progress = st.progress(0)
    status_text = st.empty()

    for idx, item_id in enumerate(ids, start=1):
        if item_type == "segments":
            endpoint = f"https://analytics.adobe.io/api/{COMPANY_ID}/segments/{item_id}"
        else:
            endpoint = f"https://analytics.adobe.io/api/{COMPANY_ID}/calculatedmetrics/{item_id}"

        status_text.text(f"Deleting ({idx}/{total}): {endpoint}")
        response = requests.delete(endpoint, headers=headers)

        # Handle 429 rate limiting
        while response.status_code == 429:
            time.sleep(0.5)
            response = requests.delete(endpoint, headers=headers)

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
            "status_code": response.status_code,
            "success": success,
            "errorCode": error_code,
            "errorDescription": error_desc,
            "raw_response": json.dumps(res, ensure_ascii=False),
        })

        progress.progress(idx / total)

    status_text.text("Done.")
    return logs


# --- STREAMLIT APP ---

st.set_page_config(page_title="Adobe Analytics Bulk Delete", layout="wide")
st.title("Adobe Analytics Bulk Delete (Segments & Calculated Metrics)")

# Keep tokens in session state
if "access_token" not in st.session_state:
    st.session_state["access_token"] = None
if "refresh_token" not in st.session_state:
    st.session_state["refresh_token"] = None

# --- OAuth callback handling ---
query_params = st.experimental_get_query_params()
if "code" in query_params:
    code = query_params["code"][0]
    try:
        tokens = exchange_code_for_tokens(code)
        st.session_state["access_token"] = tokens["access_token"]
        st.session_state["refresh_token"] = tokens.get("refresh_token")
        st.success("Authentication successful. You can now run deletions.")
        # Clear query params so we don't re-process the code on rerun
        st.experimental_set_query_params()
    except Exception as e:
        st.error(f"Failed to exchange code for tokens: {e}")

# --- Authentication section ---

if st.session_state["access_token"] is None:
    st.info("You are not authenticated.")
    if st.button("Sign in with Adobe"):
        state = "streamlit-aa-bulk-delete"  # for basic CSRF protection you can randomize this
        auth_url = build_auth_url(state)
        st.markdown(
            f"[Click here to sign in]({auth_url})",
            unsafe_allow_html=True
        )
    st.stop()
else:
    st.success("Authenticated with Adobe. Token is available for this session.")
    # Optionally, handle token expiration here with refresh_token if you see 401s later.


# --- Main tool UI (only if authenticated) ---

item_type = st.selectbox(
    "Type of component to delete:",
    options=["Segments", "Calculated Metrics"],
)

uploaded_file = st.file_uploader("Upload CSV with column 'ID'", type=["csv"])

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    if "ID" not in df.columns:
        st.error("CSV must contain a column named 'ID'.")
    else:
        st.write("Preview of IDs:")
        st.dataframe(df.head())

        if st.button("Delete Now"):
            access_token = st.session_state["access_token"]

            ids = df["ID"].astype(str).tolist()
            logs = delete_items(
                access_token,
                ids,
                item_type="segments" if item_type == "Segments" else "calculatedmetrics"
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
