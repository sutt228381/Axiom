import os
import logging
import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import pickle

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Ensure environment variables are set
os.environ["GOOGLE_CLOUD_PROJECT"] = st.secrets["web"]["project_id"]

# Define Gmail API Scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Function to authenticate with Gmail
def authenticate_gmail():
    logger.info("Starting Gmail authentication...")
    creds = None
    token_file = "token.pickle"

    # Check if token exists
    if os.path.exists(token_file):
        with open(token_file, "rb") as token:
            creds = pickle.load(token)
            logger.info("Token loaded successfully.")

    # If no valid credentials, prompt login
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logger.info("Refreshing expired token...")
            creds.refresh(Request())
        else:
            logger.info("Starting OAuth consent flow...")
            try:
                flow = InstalledAppFlow.from_client_secrets_file(
                    "client_secrets.json", SCOPES
                )
                creds = flow.run_local_server(port=8080)
                logger.info("OAuth flow completed successfully.")
            except Exception as e:
                logger.error("Error during OAuth flow: %s", e)
                raise e

        # Save the credentials for future use
        with open(token_file, "wb") as token:
            pickle.dump(creds, token)
            logger.info("Token saved successfully.")

    # Build the Gmail API client
    try:
        service = build("gmail", "v1", credentials=creds)
        logger.info("Gmail API client initialized successfully.")
        return service
    except Exception as e:
        logger.error("Error initializing Gmail API client: %s", e)
        raise e

# Function to fetch emails
def fetch_emails(service, query="label:inbox"):
    logger.info("Fetching emails with query: %s", query)
    try:
        results = service.users().messages().list(userId="me", q=query).execute()
        messages = results.get("messages", [])
        emails = []
        for msg in messages[:5]:  # Fetch only the first 5 emails
            email = service.users().messages().get(userId="me", id=msg["id"]).execute()
            snippet = email.get("snippet", "No content")
            emails.append({
                "id": msg["id"],
                "snippet": snippet
            })
        logger.info("Emails fetched successfully.")
        return emails
    except Exception as e:
        logger.error("Error fetching emails: %s", e)
        raise e

# Streamlit app layout
st.title("Gmail Dashboard")
st.write("View and analyze your Gmail data.")

# Button to trigger authentication and email fetching
if st.button("Authenticate and Fetch Emails"):
    try:
        logger.info("Button clicked: Authenticate and Fetch Emails")
        service = authenticate_gmail()
        emails = fetch_emails(service)
        if emails:
            st.write("Fetched Emails:")
            for email in emails:
                st.write(f"**ID**: {email['id']}")
                st.write(f"**Snippet**: {email['snippet']}")
                st.write("---")
        else:
            st.write("No emails found.")
    except Exception as e:
        st.error(f"An error occurred during authentication: {e}")
