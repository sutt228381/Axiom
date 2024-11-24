import os
import json
import logging
import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

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

# Create client_secrets.json dynamically
def create_client_secrets():
    """Generate client_secrets.json from Streamlit secrets."""
    try:
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
    except Exception as e:
        st.error(f"Error creating client_secrets.json: {str(e)}")
        logger.error(f"Error creating client_secrets.json: {str(e)}", exc_info=True)

# Authenticate Gmail
def authenticate_gmail():
    """Authenticate Gmail API and return the service object."""
    try:
        create_client_secrets()
        flow = InstalledAppFlow.from_client_secrets_file("client_secrets.json", SCOPES)
        creds = flow.run_local_server(port=8080)  # Use port 8080
        # Save the credentials for future use
        with open(TOKEN_FILE, "w") as token:
            json.dump(creds.to_json(), token)
        logger.info("Token saved successfully.")
        return build("gmail", "v1", credentials=flow.credentials)
    except Exception as e:
        st.error(f"An error occurred during authentication: {str(e)}")
        logger.error(f"Error during Gmail authentication: {str(e)}", exc_info=True)
        return None

# Fetch emails
def fetch_emails(service):
    """Fetch emails from Gmail and display them."""
    try:
        results = service.users().messages().list(userId="me", q="label:inbox").execute()
        messages = results.get("messages", [])
        if not messages:
            st.write("No emails found.")
            return
        for message in messages[:5]:  # Limit to first 5 emails
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            snippet = msg.get("snippet", "No content")
            st.write(f"**Snippet**: {snippet}")
    except Exception as e:
        st.error(f"An error occurred while fetching emails: {str(e)}")
        logger.error(f"Error during email fetching: {str(e)}", exc_info=True)

# Main app
def main():
    st.title("Gmail Dashboard")
    st.write("Authenticate and view your Gmail inbox snippets.")
    if st.button("Authenticate and Fetch Emails"):
        service = authenticate_gmail()
        if service:
            fetch_emails(service)

if __name__ == "__main__":
    main()
