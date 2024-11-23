import os
import logging
import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import pickle
from google.auth.transport.requests import Request
from threading import Thread
import time

# Configure logging to write to a file and stream to the terminal
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log"),  # Log to a file named 'app.log'
        logging.StreamHandler()          # Also output logs to the terminal
    ]
)
logger = logging.getLogger(__name__)

logger.info("App started successfully.")

# Define Gmail API Scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


class OAuthTimeoutException(Exception):
    pass


def authenticate_with_timeout(flow, timeout=60):
    """Run the OAuth flow with a timeout using threading."""
    result = {"creds": None, "error": None}

    def run_flow():
        try:
            result["creds"] = flow.run_local_server(port=0)
        except Exception as e:
            result["error"] = e

    thread = Thread(target=run_flow)
    thread.start()
    thread.join(timeout)

    if thread.is_alive():
        raise OAuthTimeoutException("Authentication process timed out.")
    if result["error"]:
        raise result["error"]
    return result["creds"]


def authenticate_gmail():
    """Authenticate with the Gmail API."""
    logger.info("Starting Gmail authentication...")
    token_file = 'token.pickle'
    creds = None

    # Check if a token already exists
    if os.path.exists(token_file):
        logger.info("Loading existing token...")
        with open(token_file, 'rb') as token:
            creds = pickle.load(token)

    # If no valid token, initiate OAuth flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logger.info("Refreshing expired token...")
            creds.refresh(Request())
            logger.info("Token refreshed successfully.")
        else:
            logger.info("Initiating OAuth flow...")
            try:
                # Load credentials from Streamlit Secrets
                flow = InstalledAppFlow.from_client_config(
                    st.secrets["gmail_credentials"], SCOPES
                )
                logger.info("Opening OAuth consent screen...")
                creds = authenticate_with_timeout(flow, timeout=60)  # Thread-based timeout
                logger.info("OAuth flow completed successfully.")
            except OAuthTimeoutException:
                logger.error("Authentication process timed out.")
                st.error("Authentication process timed out. Please try again.")
                raise OAuthTimeoutException
            except Exception as e:
                logger.error("Error during OAuth flow:", exc_info=True)
                st.error("Failed to complete OAuth authentication. Please try again.")
                raise e

        # Save the token for future use
        with open(token_file, 'wb') as token:
            pickle.dump(creds, token)
            logger.info("Token saved successfully.")

    # Build Gmail API client
    try:
        service = build('gmail', 'v1', credentials=creds)
        logger.info("Gmail API client initialized successfully.")
        return service
    except Exception as e:
        logger.error("Error initializing Gmail API client:", exc_info=True)
        st.error("Failed to initialize Gmail API client. Please check your credentials and try again.")
        raise e


def fetch_emails(service, query="label:inbox"):
    """Fetch emails based on a query."""
    try:
        logger.info("Fetching emails with query: %s", query)
        results = service.users().messages().list(userId='me', q=query).execute()
        messages = results.get('messages', [])
        email_data = []
        if not messages:
            logger.info("No emails found.")
            st.write("No emails found.")
            return email_data
        logger.info("Found %d messages.", len(messages))
        for msg in messages[:5]:  # Fetch only the first 5 emails
            email = service.users().messages().get(userId='me', id=msg['id']).execute()
            snippet = email.get('snippet', 'No content')  # Extract email snippet
            email_data.append({
                'id': msg['id'],
                'snippet': snippet,
                'internalDate': email.get('internalDate'),
                'payload': email.get('payload', {}).get('headers', [])
            })
        logger.info("Fetched %d emails.", len(email_data))
        return email_data
    except Exception as e:
        logger.error("Error while fetching emails:", exc_info=True)
        st.error("Failed to fetch emails. Please try again.")
        raise e


def display_logs():
    """Display logs in the Streamlit UI."""
    if os.path.exists("app.log"):
        with open("app.log", "r") as log_file:
            st.text(log_file.read())


# Streamlit App
st.title("Gmail Dashboard")
st.write("A dashboard to view and analyze your Gmail data.")

# Button to trigger email fetching
if st.button("Fetch Emails"):
    try:
        st.write("Authenticating with Gmail...")
        service = authenticate_gmail()  # Authenticate Gmail API
        st.write("Fetching emails...")
        emails = fetch_emails(service)  # Fetch emails
        if emails:
            st.write("Fetched Emails:")
            for email in emails:
                st.write(f"**ID**: {email['id']}")
                st.write(f"**Snippet**: {email['snippet']}")
                st.write("---")
        else:
            st.write("No emails to display.")
    except Exception as e:
        st.error(f"An error occurred: {e}")
        logger.error("An unexpected error occurred.", exc_info=True)

# Button to show logs
if st.button("Show Logs"):
    display_logs()

# Footer
st.write("Powered by Gmail API and Streamlit.")
