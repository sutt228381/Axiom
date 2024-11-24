import os
import logging
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from logging.handlers import RotatingFileHandler
import streamlit as st

# Set up environment variables
os.environ["GOOGLE_CLOUD_PROJECT"] = st.secrets["web"]["project_id"]

# Set up logging
log_file = "app.log"
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=2)]
)
logger = logging.getLogger(__name__)

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticate_gmail():
    logger.info("Starting Gmail authentication...")
    creds = None

    # Use Streamlit Secrets for credentials
    credentials_file = {
        "installed": {
            "client_id": st.secrets["web"]["client_id"],
            "project_id": st.secrets["web"]["project_id"],
            "auth_uri": st.secrets["web"]["auth_uri"],
            "token_uri": st.secrets["web"]["token_uri"],
            "auth_provider_x509_cert_url": st.secrets["web"]["auth_provider_x509_cert_url"],
            "client_secret": st.secrets["web"]["client_secret"],
            "redirect_uris": st.secrets["web"]["redirect_uris"]
        }
    }

    try:
        flow = InstalledAppFlow.from_client_config(credentials_file, SCOPES)
        logger.info("Starting manual OAuth flow...")
        creds = flow.run_console()  # Manual flow for Streamlit Cloud
        logger.info("OAuth flow completed successfully.")
    except Exception as e:
        logger.error(f"Error during OAuth flow: {e}")
        raise e

    # Build the Gmail API client
    try:
        service = build('gmail', 'v1', credentials=creds)
        logger.info("Gmail API client initialized successfully.")
        return service
    except Exception as e:
        logger.error(f"Error initializing Gmail API client: {e}")
        raise e

def fetch_emails(service, query="label:inbox"):
    logger.info(f"Fetching emails with query: {query}")
    try:
        results = service.users().messages().list(userId='me', q=query).execute()
        messages = results.get('messages', [])
        emails = []
        for msg in messages[:5]:  # Fetch first 5 emails
            email = service.users().messages().get(userId='me', id=msg['id']).execute()
            snippet = email.get('snippet', 'No content')
            emails.append(snippet)
        return emails
    except Exception as e:
        logger.error(f"Error fetching emails: {e}")
        raise e

# Streamlit App
st.title("Gmail Dashboard")
st.write("Authenticate with Gmail and fetch your latest emails.")

if st.button("Authenticate and Fetch Emails"):
    try:
        logger.info("Button clicked: Authenticate and Fetch Emails")
        st.write("Authenticating with Gmail...")
        service = authenticate_gmail()
        st.write("Fetching emails...")
        emails = fetch_emails(service)
        if emails:
            st.write("Fetched Emails:")
            for email in emails:
                st.write(email)
        else:
            st.write("No emails found.")
    except Exception as e:
        st.error(f"An error occurred: {e}")
