import os
import logging
import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Set Google Cloud project details
os.environ["GOOGLE_CLOUD_PROJECT"] = "concise-rex-442402-b5"

# Gmail API Scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticate_gmail():
    logger.info("Starting Gmail authentication...")
    try:
        # Use manual flow
        flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
        auth_url, _ = flow.authorization_url(prompt='consent')
        st.write(f"[Authorize Gmail Access]({auth_url})")

        # Ask user to enter the authorization code
        auth_code = st.text_input("Enter the authorization code here:")
        if auth_code:
            flow.fetch_token(code=auth_code)
            logger.info("OAuth flow completed successfully.")
            return flow.credentials
    except Exception as e:
        logger.error("Error during OAuth flow: %s", e)
        st.error("Authentication failed.")
        return None

def fetch_emails(service, query="label:inbox"):
    try:
        results = service.users().messages().list(userId='me', q=query).execute()
        messages = results.get('messages', [])
        emails = []
        if not messages:
            st.write("No emails found.")
            return emails

        for msg in messages[:5]:  # Fetch only the first 5 emails
            email = service.users().messages().get(userId='me', id=msg['id']).execute()
            snippet = email.get('snippet', 'No content')
            emails.append({"id": msg['id'], "snippet": snippet})
        return emails
    except Exception as e:
        logger.error("Error fetching emails: %s", e)
        st.error("Failed to fetch emails.")
        return []

# Streamlit UI
st.title("Gmail Dashboard")
st.write("View and analyze your Gmail data.")

if st.button("Authenticate and Fetch Emails"):
    creds = authenticate_gmail()
    if creds:
        service = build('gmail', 'v1', credentials=creds)
        emails = fetch_emails(service)
        if emails:
            for email in emails:
                st.write(f"**ID**: {email['id']}")
                st.write(f"**Snippet**: {email['snippet']}")
                st.write("---")
        else:
            st.write("No emails fetched.")

st.write("Powered by Gmail API and Streamlit.")
