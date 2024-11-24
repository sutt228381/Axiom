import os
import logging
import streamlit as st
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Google Cloud Project setup
os.environ["GOOGLE_CLOUD_PROJECT"] = st.secrets["web"]["project_id"]

# OAuth Configuration
CLIENT_CONFIG = {
    "web": {
        "client_id": st.secrets["web"]["client_id"],
        "project_id": st.secrets["web"]["project_id"],
        "auth_uri": st.secrets["web"]["auth_uri"],
        "token_uri": st.secrets["web"]["token_uri"],
        "auth_provider_x509_cert_url": st.secrets["web"]["auth_provider_x509_cert_url"],
        "client_secret": st.secrets["web"]["client_secret"],
    }
}
REDIRECT_URI = st.secrets["web"]["redirect_uris"][0]
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Initialize session state
if "credentials" not in st.session_state:
    st.session_state["credentials"] = None


# Function to generate authorization URL
def authenticate_user():
    try:
        flow = Flow.from_client_config(CLIENT_CONFIG, scopes=SCOPES)
        flow.redirect_uri = REDIRECT_URI
        auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline")
        return auth_url, flow
    except Exception as e:
        logger.error("Error generating auth URL:", exc_info=True)
        st.error(f"An error occurred during authentication: {e}")
        return None, None


# Function to exchange authorization code for credentials
def exchange_code(flow, authorization_code):
    try:
        flow.fetch_token(code=authorization_code)
        credentials = flow.credentials
        return credentials
    except Exception as e:
        logger.error("Error exchanging authorization code:", exc_info=True)
        st.error(f"An error occurred during token exchange: {e}")
        return None


# Function to fetch emails
def fetch_emails(credentials):
    try:
        service = build("gmail", "v1", credentials=credentials)
        results = service.users().messages().list(userId="me", maxResults=10).execute()
        messages = results.get("messages", [])
        return messages
    except Exception as e:
        logger.error("Error fetching emails:", exc_info=True)
        st.error(f"An error occurred during email fetching: {e}")
        return None


# Streamlit App
st.title("Gmail Dashboard")

# Authentication button
if not st.session_state["credentials"]:
    st.write("To begin, click 'Authenticate' to log into your Gmail account.")
    if st.button("Authenticate"):
        auth_url, flow = authenticate_user()
        if auth_url:
            st.write(f"[Click here to authenticate]({auth_url})")
            st.write("Once you've authenticated, paste the authorization code below.")
            
            # Input for authorization code
            authorization_code = st.text_input("Enter Authorization Code:")

            if st.button("Submit Authorization Code"):
                credentials = exchange_code(flow, authorization_code)
                if credentials:
                    st.session_state["credentials"] = credentials
                    st.success("Authentication successful! You can now fetch emails.")

# Fetch Emails button
if st.session_state["credentials"]:
    st.write("You are authenticated. Click 'Fetch Emails' to retrieve your messages.")
    if st.button("Fetch Emails"):
        emails = fetch_emails(st.session_state["credentials"])
        if emails:
            st.write("Fetched Emails:")
            for msg in emails:
                st.write(f"Message ID: {msg['id']}")
