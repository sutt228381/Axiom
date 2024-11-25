import os
import json
import streamlit as st
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import requests
from google.oauth2.credentials import Credentials
from googleapiclient.errors import HttpError
import logging

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants for token and credentials
TOKEN_FILE = "token.json"
CLIENT_SECRETS_FILE = "client_secrets.json"

# Step 1: Function to create client_secrets.json dynamically
def create_client_secrets():
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
                "javascript_origins": st.secrets["web"]["javascript_origins"],
            }
        }
        with open(CLIENT_SECRETS_FILE, "w") as file:
            json.dump(client_secrets, file)
        logger.info("Client secrets file created successfully.")
    except Exception as e:
        st.error(f"Error creating client_secrets.json: {e}")
        logger.error(f"Error creating client_secrets.json: {e}")

# Step 2: Authenticate user and fetch Google OAuth token
def authenticate_user():
    try:
        # Check if token file exists
        creds = None
        if os.path.exists(TOKEN_FILE):
            creds = Credentials.from_authorized_user_file(TOKEN_FILE)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = Flow.from_client_secrets_file(
                    CLIENT_SECRETS_FILE,
                    scopes=["https://www.googleapis.com/auth/gmail.readonly"],
                    redirect_uri=st.secrets["web"]["redirect_uris"][0],
                )
                auth_url, _ = flow.authorization_url(prompt="consent")
                st.markdown(f"### [Authenticate Here]({auth_url})")
                auth_code = st.text_input("Enter the authorization code:")
                if st.button("Submit Authorization Code"):
                    flow.fetch_token(code=auth_code)
                    creds = flow.credentials
                    # Save the token
                    with open(TOKEN_FILE, "w") as token:
                        token.write(creds.to_json())

        return build("gmail", "v1", credentials=creds)
    except Exception as e:
        st.error(f"An error occurred during authentication: {e}")
        logger.error(f"An error occurred during authentication: {e}")

# Step 3: Fetch emails from the authenticated Gmail account
def fetch_emails(service):
    try:
        results = service.users().messages().list(userId="me", labelIds=["INBOX"], maxResults=10).execute()
        messages = results.get("messages", [])

        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            st.write(f"Snippet: {msg['snippet']}")
    except HttpError as error:
        st.error(f"An error occurred while fetching emails: {error}")
        logger.error(f"An error occurred while fetching emails: {error}")

# Step 4: Streamlit app UI and main function
def main():
    st.title("Gmail Dashboard")
    st.write("Authenticate to view your Gmail inbox.")
    
    # Create the client_secrets.json
    create_client_secrets()
    
    # Authentication and email fetching
    if st.button("Authenticate and Fetch Emails"):
        service = authenticate_user()
        if service:
            fetch_emails(service)

if __name__ == "__main__":
    main()
