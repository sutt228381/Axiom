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

def authenticate_user():
    create_client_secrets_file()
    try:
        if "creds" in st.session_state:
            return st.session_state["creds"]

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
            st.session_state["creds"] = creds
            logger.info("Token saved to session state.")
            return creds
    except Exception as e:
        logger.error(f"Error during Gmail authentication: {e}")
        st.error(f"Error during Gmail authentication: {e}")
        return None

def fetch_emails(service, query):
    try:
        st.subheader(f"Fetching emails with query: '{query}'")
        results = service.users().messages().list(userId="me", q=query, maxResults=10).execute()
        messages = results.get("messages", [])
        
        if not messages:
            st.info("No messages found.")
            return

        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            snippet = msg.get("snippet", "No snippet available")
            headers = {h['name']: h['value'] for h in msg['payload']['headers']}
            subject = headers.get("Subject", "No Subject")
            date = headers.get("Date", "No Date")
            st.markdown(f"**Subject:** {subject}")
            st.markdown(f"**Date:** {date}")
            st.text_area("Snippet", snippet, height=100, disabled=True)
            st.divider()
    except HttpError as error:
        logger.error(f"An error occurred: {error}")
        st.error(f"An error occurred: {error}")

def main():
    st.title("Gmail Dashboard")
    st.write("Enter your email query to filter relevant emails.")

    # Input for email query
    query = st.text_input("Enter a topic or query to search your emails (e.g., 'TDBank', 'Invoice', etc.):")
    if not query:
        st.info("Please enter a query to search your emails.")
        return

    # Authenticate and fetch emails
    creds = authenticate_user()
    if creds:
        try:
            service = build("gmail", "v1", credentials=creds)
            st.success("Authentication successful. Fetching emails...")
            fetch_emails(service, query)
        except Exception as e:
            logger.error(f"An error occurred: {e}")
            st.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
