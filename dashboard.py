import os
import json
import streamlit as st
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Paths and constants
CLIENT_SECRETS_FILE = "client_secrets.json"
TOKEN_FILE = "token.json"

# Function to create the client_secrets.json file
def create_client_secrets_file():
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
        with open(CLIENT_SECRETS_FILE, "w") as f:
            json.dump(client_secrets, f)
        logger.info("Client secrets file created successfully.")
    except Exception as e:
        logger.error(f"Error creating client_secrets.json: {e}")
        st.error(f"Error creating client_secrets.json: {e}")

# Function to authenticate user with Gmail API
def authenticate_user():
    create_client_secrets_file()
    try:
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
            redirect_uri=st.secrets["web"]["redirect_uris"][0]
        )
        auth_url, _ = flow.authorization_url(prompt="consent")
        st.write(f"[Click here to authenticate]({auth_url})")
        code = st.experimental_get_query_params().get("code")
        if code:
            flow.fetch_token(code=code[0])
            creds = flow.credentials
            with open(TOKEN_FILE, "w") as token:
                token.write(creds.to_json())
            logger.info("Token saved successfully.")
            return creds
    except Exception as e:
        logger.error(f"Error during Gmail authentication: {e}")
        st.error(f"Error during Gmail authentication: {e}")
        return None

# Function to load credentials from the token file
def load_credentials():
    try:
        if os.path.exists(TOKEN_FILE):
            with open(TOKEN_FILE, "r") as token:
                creds = json.load(token)
            logger.info("Loaded credentials from token file.")
            return creds
    except Exception as e:
        logger.error(f"Error loading credentials: {e}")
        return None

# Function to fetch and display emails
def fetch_emails(service, query):
    try:
        results = service.users().messages().list(userId="me", q=query, maxResults=10).execute()
        messages = results.get("messages", [])
        if not messages:
            st.write("No messages found for your query.")
            return
        
        st.write(f"Displaying messages for: '{query}'")
        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            snippet = msg.get("snippet", "No snippet available")
            st.write(f"Message: {snippet}")
    except HttpError as error:
        logger.error(f"An error occurred: {error}")
        st.error(f"An error occurred: {error}")

# Main app logic
def main():
    st.title("Gmail Dashboard")

    # Input for email address
    user_email = st.text_input("Enter your email address to authenticate:")
    if not user_email:
        st.warning("Please enter your email address to proceed.")
        return

    # Input for query
    query = st.text_input("What would you like to view? (e.g., 'TDBank', 'Amazon', etc.)", value="")

    # Authenticate or load existing credentials
    if "creds" not in st.session_state:
        if st.button("Authenticate"):
            creds = authenticate_user()
            if creds:
                st.session_state.creds = creds
                st.success("Authentication successful!")
    else:
        creds = st.session_state.creds

    # Fetch emails using authenticated credentials
    if creds and st.button("Fetch Emails"):
        try:
            service = build("gmail", "v1", credentials=creds)
            fetch_emails(service, query)
        except Exception as e:
            logger.error(f"Error fetching emails: {e}")
            st.error(f"Error fetching emails: {e}")

if __name__ == "__main__":
    main()
