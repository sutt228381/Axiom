import os
import json
import logging
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import streamlit as st

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("app.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# Define Gmail API Scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Load test users for validation
AUTHORIZED_TEST_USERS = ["sortsyai@gmail.com", "adammsutton@gmail.com"]


# Authentication for Gmail
def authenticate_gmail():
    logger.info("Starting Gmail authentication...")
    try:
        flow = InstalledAppFlow.from_client_secrets_file('client_secrets.json', SCOPES)
        creds = flow.run_local_server(port=8080)
        service = build('gmail', 'v1', credentials=creds)
        logger.info("Gmail API client initialized successfully.")
        return service
    except Exception as e:
        logger.error("Error during Gmail authentication: %s", e)
        raise e


# Fetch Emails
def fetch_emails(service, query="label:inbox"):
    try:
        logger.info("Fetching emails with query: %s", query)
        results = service.users().messages().list(userId='me', q=query).execute()
        messages = results.get('messages', [])
        emails = []
        for msg in messages[:5]:  # Fetch only the first 5 emails
            email = service.users().messages().get(userId='me', id=msg['id']).execute()
            emails.append(email.get('snippet', 'No content'))
        return emails
    except Exception as e:
        logger.error("Error fetching emails: %s", e)
        return []


# Streamlit UI
st.title("Gmail Dashboard")

# Email input for test user validation
user_email = st.text_input("Enter your email address to proceed:")
if st.button("Authenticate and Fetch Emails"):
    if user_email.lower() in (email.lower() for email in AUTHORIZED_TEST_USERS):
        try:
            service = authenticate_gmail()
            emails = fetch_emails(service)
            if emails:
                st.write("Fetched Emails:")
                for email in emails:
                    st.write(email)
            else:
                st.write("No emails found.")
        except Exception as e:
            st.error(f"An error occurred during authentication: {e}")
    else:
        st.error("Email is not authorized. Please use a valid test email.")

st.write("Powered by Gmail API and Streamlit.")
