import os
import json
import logging
import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

# Configure logging
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
    handlers=[logging.FileHandler("app.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# Constants
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
TOKEN_FILE = "token.json"

# Dynamic secrets setup
def create_client_secrets():
    """Create client_secrets.json dynamically from Streamlit secrets."""
    client_secrets = {
        "web": {
            "client_id": st.secrets["web"]["client_id"],
            "project_id": st.secrets["web"]["project_id"],
            "auth_uri": st.secrets["web"]["auth_uri"],
            "token_uri": st.secrets["web"]["token_uri"],
            "auth_provider_x509_cert_url": st.secrets["web"]["auth_provider_x509_cert_url"],
            "client_secret": st.secrets["web"]["client_secret"],
            "redirect_uris": st.secrets["web"]["redirect_uris"],
        }
    }
    with open("client_secrets.json", "w") as f:
        json.dump(client_secrets, f)
    logger.info("Client secrets file created successfully.")

# Authentication
def authenticate_gmail():
    """Authenticate with Gmail API using OAuth."""
    logger.info("Starting Gmail authentication...")
    try:
        # Ensure client_secrets.json is created
        create_client_secrets()
        flow = InstalledAppFlow.from_client_secrets_file("client_secrets.json", SCOPES)
        auth_url, _ = flow.authorization_url(prompt="consent")
        st.write(f"Authenticate here: [Click this link]({auth_url})")
        auth_code = st.text_input("Enter the authorization code:")
        if auth_code:
            creds = flow.fetch_token(code=auth_code)
            with open(TOKEN_FILE, "w") as token_file:
                json.dump(creds, token_file)
            logger.info("Token saved successfully.")
            return build("gmail", "v1", credentials=flow.credentials)
    except Exception as e:
        st.error(f"An error occurred during authentication: {str(e)}")
        logger.error(f"Error during Gmail authentication: {str(e)}", exc_info=True)
        return None

# Fetch emails
def fetch_emails(service):
    """Fetch and display emails."""
    logger.info("Fetching emails...")
    try:
        results = service.users().messages().list(userId="me", q="label:inbox").execute()
        messages = results.get("messages", [])
        if not messages:
            st.write("No emails found.")
            return
        for message in messages[:5]:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            snippet = msg.get("snippet", "No content")
            st.write(f"**Snippet**: {snippet}")
    except Exception as e:
        st.error(f"An error occurred while fetching emails: {str(e)}")
        logger.error(f"Error during email fetching: {str(e)}", exc_info=True)

# Main App
def main():
    st.title("Gmail Dashboard")
    st.write("Authenticate and view your Gmail inbox snippets.")
    
    # Google Cloud Project check
    if "project_id" in st.secrets["web"]:
        logger.info(f"Google Cloud Project: {st.secrets['web']['project_id']}")

    if st.button("Authenticate and Fetch Emails"):
        logger.info("Button clicked: Authenticate and Fetch Emails")
        service = authenticate_gmail()
        if service:
            fetch_emails(service)

if __name__ == "__main__":
    main()
