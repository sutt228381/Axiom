import os
import logging
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import streamlit as st

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Set environment variables
os.environ["GOOGLE_CLOUD_PROJECT"] = "concise-rex-442402-b5"
os.environ["NO_GCE_CHECK"] = "true"  # Avoid Compute Engine Metadata warnings

# Gmail API Scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


# Function to authenticate the user with OAuth
def authenticate_gmail():
    logger.info("Starting Gmail authentication...")
    flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)

    try:
        creds = flow.run_local_server(port=0)  # Dynamically select an available port
        logger.info("OAuth consent completed successfully.")
    except Exception as e:
        logger.error("Error during OAuth consent flow: %s", e)
        raise e

    # Initialize Gmail API client
    try:
        service = build('gmail', 'v1', credentials=creds)
        logger.info("Gmail API client initialized successfully.")
        return service
    except Exception as e:
        logger.error("Error initializing Gmail API client: %s", e)
        raise e


# Fetch emails dynamically
def fetch_emails(service, query="label:inbox"):
    logger.info("Fetching emails with query: %s", query)
    try:
        results = service.users().messages().list(userId='me', q=query).execute()
        messages = results.get('messages', [])
        emails = []

        if not messages:
            st.write("No emails found.")
            return emails

        for msg in messages[:5]:
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
st.write("A dashboard to view and analyze your Gmail data.")

# Authenticate and fetch emails
if st.button("Authenticate and Fetch Emails"):
    try:
        service = authenticate_gmail()
        emails = fetch_emails(service)
        if emails:
            st.write("Fetched Emails:")
            for email in emails:
                st.write(f"**ID**: {email['id']}")
                st.write(f"**Snippet**: {email['snippet']}")
                st.write("---")
    except Exception as e:
        st.error(f"An error occurred: {e}")

st.write("Powered by Gmail API and Streamlit.")
