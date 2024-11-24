import os
import json
import logging
import streamlit as st
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import pickle

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# App title
st.title("Gmail Dashboard")

# Load Google credentials dynamically
def create_client_secrets_file():
    client_secrets = {
        "web": {
            "client_id": st.secrets["google"]["client_id"],
            "project_id": st.secrets["google"]["project_id"],
            "auth_uri": st.secrets["google"]["auth_uri"],
            "token_uri": st.secrets["google"]["token_uri"],
            "auth_provider_x509_cert_url": st.secrets["google"]["auth_provider_x509_cert_url"],
            "client_secret": st.secrets["google"]["client_secret"],
            "redirect_uris": st.secrets["google"]["redirect_uris"]
        }
    }
    with open("client_secrets.json", "w") as f:
        json.dump(client_secrets, f)
        logger.info("Client secrets file created successfully.")

# Authenticate Gmail
def authenticate_gmail():
    token_file = "token.json"
    creds = None

    # Check if a token exists
    if os.path.exists(token_file):
        logger.info("Loading existing token.")
        with open(token_file, "rb") as token:
            creds = pickle.load(token)

    # If no valid token, initiate OAuth flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            logger.info("Token refreshed successfully.")
        else:
            logger.info("Starting OAuth flow...")
            flow = Flow.from_client_secrets_file(
                "client_secrets.json",
                scopes=["https://www.googleapis.com/auth/gmail.readonly"],
            )
            flow.redirect_uri = st.secrets["google"]["redirect_uris"][0]
            auth_url, _ = flow.authorization_url(prompt="consent")
            st.write(f"[Authenticate with Google]({auth_url})")

            auth_code = st.text_input("Enter the authentication code here:")
            if auth_code:
                try:
                    flow.fetch_token(code=auth_code)
                    creds = flow.credentials
                    with open(token_file, "wb") as token:
                        pickle.dump(creds, token)
                        logger.info("Token saved successfully.")
                except Exception as e:
                    st.error(f"Authentication failed: {e}")
                    logger.error("Error during authentication.", exc_info=True)
                    return None

    try:
        service = build("gmail", "v1", credentials=creds)
        logger.info("Gmail API client initialized successfully.")
        return service
    except Exception as e:
        st.error(f"Failed to initialize Gmail API client: {e}")
        logger.error("Error initializing Gmail API client.", exc_info=True)
        return None

# Fetch emails
def fetch_emails(service, query="label:inbox"):
    try:
        st.info("Fetching emails...")
        results = service.users().messages().list(userId="me", q=query).execute()
        messages = results.get("messages", [])
        if not messages:
            st.write("No emails found.")
            return

        for msg in messages[:5]:  # Fetch up to 5 emails
            email = service.users().messages().get(userId="me", id=msg["id"]).execute()
            snippet = email.get("snippet", "No content available")
            st.write(f"**Snippet**: {snippet}")
    except Exception as e:
        st.error(f"Failed to fetch emails: {e}")
        logger.error("Error fetching emails.", exc_info=True)

# Main app
if __name__ == "__main__":
    st.write("Authenticate and view your Gmail inbox snippets.")

    # Create client_secrets.json dynamically
    create_client_secrets_file()

    if st.button("Authenticate and Fetch Emails"):
        logger.info("Button clicked: Authenticate and Fetch Emails")
        service = authenticate_gmail()
        if service:
            fetch_emails(service)
