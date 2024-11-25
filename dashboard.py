import os
import json
import logging
import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define Gmail API scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Function to authenticate the user
def authenticate_user():
    client_secrets_file = "client_secrets.json"
    try:
        flow = InstalledAppFlow.from_client_secrets_file(client_secrets_file, SCOPES)
        creds = flow.run_local_server(port=8080)
        return creds
    except Exception as e:
        logger.error(f"Error during authentication: {e}")
        st.error(f"An error occurred during authentication: {e}")
        return None

# Function to fetch emails
def fetch_emails(service):
    try:
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=10).execute()
        messages = results.get('messages', [])
        if not messages:
            st.write("No messages found.")
            return

        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            snippet = msg.get('snippet', 'No snippet available')
            st.write(f"Email Snippet: {snippet}")
    except HttpError as error:
        logger.error(f"An error occurred: {error}")
        st.error(f"An error occurred: {error}")

# Main function
def main():
    st.title("Gmail Dashboard")
    st.write("Authenticate and fetch your emails.")

    if st.button("Authenticate and Fetch Emails"):
        creds = authenticate_user()
        if creds:
            service = build('gmail', 'v1', credentials=creds)
            fetch_emails(service)

if __name__ == "__main__":
    main()
