import os
import json
import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Disable GCE Metadata access
os.environ["NO_GCE_CHECK"] = "true"

# Google API Scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def create_client_secrets():
    """Generate the client_secrets.json file dynamically from Streamlit secrets."""
    try:
        client_secrets = {
            "web": {
                "client_id": st.secrets["web"]["client_id"],
                "project_id": st.secrets["web"]["project_id"],
                "auth_uri": st.secrets["web"]["auth_uri"],
                "token_uri": st.secrets["web"]["token_uri"],
                "auth_provider_x509_cert_url": st.secrets["web"]["auth_provider_x509_cert_url"],
                "client_secret": st.secrets["web"]["client_secret"],
                "redirect_uris": st.secrets["web"]["redirect_uris"]
            }
        }
        with open("client_secrets.json", "w") as f:
            json.dump(client_secrets, f)
        logger.info("Client secrets file created successfully.")
    except Exception as e:
        logger.error(f"Error creating client_secrets.json: {e}")
        st.error(f"Error creating client_secrets.json: {e}")

def authenticate_user():
    """Authenticate the user via OAuth and return the Gmail service object."""
    creds = None
    token_file = "token.json"
    
    # Load existing token if available
    if os.path.exists(token_file):
        with open(token_file, "r") as token:
            creds = Credentials.from_authorized_user_info(json.load(token), SCOPES)

    # If credentials are invalid or not available, authenticate the user
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("client_secrets.json", SCOPES)
            creds = flow.run_local_server(port=8080)

        # Save credentials for future use
        with open(token_file, "w") as token:
            token.write(creds.to_json())

    return build('gmail', 'v1', credentials=creds)

def fetch_emails(service):
    """Fetch emails using the Gmail API."""
    try:
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=10).execute()
        messages = results.get('messages', [])
        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            snippet = msg.get('snippet')
            st.write(snippet)
    except Exception as e:
        logger.error(f"Error fetching emails: {e}")
        st.error(f"Error fetching emails: {e}")

def main():
    """Main function to run the Streamlit app."""
    st.title("Gmail Dashboard")
    st.write("Authenticate and view your Gmail inbox snippets.")
    
    if st.button("Authenticate and Fetch Emails"):
        create_client_secrets()
        try:
            service = authenticate_user()
            if service:
                fetch_emails(service)
        except Exception as e:
            logger.error(f"Error during Gmail authentication: {e}")
            st.error(f"An error occurred during authentication: {e}")

if __name__ == "__main__":
    main()
