import streamlit as st
import json
import os
import logging
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Constants
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
TOKEN_FILE = "token.json"

# Function to create client_secrets.json dynamically
def create_client_secrets():
    try:
        secrets = st.secrets["web"]
        client_secrets = {
            "installed": {
                "client_id": secrets["client_id"],
                "project_id": secrets["project_id"],
                "auth_uri": secrets["auth_uri"],
                "token_uri": secrets["token_uri"],
                "auth_provider_x509_cert_url": secrets["auth_provider_x509_cert_url"],
                "client_secret": secrets["client_secret"],
                "redirect_uris": secrets["redirect_uris"],
            }
        }
        with open("client_secrets.json", "w") as f:
            json.dump(client_secrets, f)
        logger.info("Client secrets file created successfully.")
    except Exception as e:
        logger.error(f"Error creating client_secrets.json: {e}")
        st.error(f"Error creating client_secrets.json: {e}")

# Gmail authentication function
def authenticate_gmail():
    logger.info("Starting Gmail authentication...")
    creds = None

    # Load credentials from file if available
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    # If no valid credentials, initiate OAuth flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            logger.info("Token refreshed successfully.")
        else:
            logger.info("Initiating OAuth flow...")
            create_client_secrets()
            flow = InstalledAppFlow.from_client_secrets_file("client_secrets.json", SCOPES)
            creds = flow.run_local_server(port=8080)
            with open(TOKEN_FILE, "w") as token_file:
                token_file.write(creds.to_json())
                logger.info("Token saved successfully.")

    # Build Gmail API service
    try:
        service = build("gmail", "v1", credentials=creds)
        logger.info("Gmail API client initialized successfully.")
        return service
    except Exception as e:
        logger.error(f"Error initializing Gmail API client: {e}")
        st.error(f"Error initializing Gmail API client: {e}")
        return None

# Fetch emails function
def fetch_emails(service):
    try:
        logger.info("Fetching emails...")
        results = service.users().messages().list(userId="me", maxResults=10).execute()
        messages = results.get("messages", [])
        if not messages:
            st.write("No emails found.")
            return

        st.write("Here are the latest emails:")
        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            st.write(f"Snippet: {msg['snippet']}")
    except Exception as e:
        logger.error(f"Error fetching emails: {e}")
        st.error(f"Error fetching emails: {e}")

# Streamlit app
def main():
    st.title("Gmail Dashboard")
    st.write("Authenticate and view your Gmail inbox snippets.")

    if st.button("Authenticate and Fetch Emails"):
        service = authenticate_gmail()
        if service:
            fetch_emails(service)

if __name__ == "__main__":
    main()
