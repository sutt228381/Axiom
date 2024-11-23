import os
import logging
import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import pickle
from google.auth.transport.requests import Request

# Configure logging
LOG_FILE = "app.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),  # Log to a file
        logging.StreamHandler()         # Also log to the console
    ]
)
logger = logging.getLogger(__name__)

# Set up environment variables
os.environ["NO_GCE_CHECK"] = "true"  # Suppress Compute Engine warning

# Function to clear the log file
def clear_log_file():
    """Clears the log file at the start of each session."""
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as log_file:
            log_file.truncate()
clear_log_file()
logger.info("Log file initialized successfully.")

# Gmail API scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Authenticate Gmail API
def authenticate_gmail():
    """Authenticate with the Gmail API using OAuth flow."""
    logger.info("Starting Gmail authentication...")
    token_file = 'token.pickle'
    creds = None

    # Check for existing token
    if os.path.exists(token_file):
        logger.info("Token file exists. Loading existing token...")
        with open(token_file, 'rb') as token:
            creds = pickle.load(token)

    # If no valid token, initiate OAuth flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logger.info("Refreshing expired token...")
            creds.refresh(Request())
            logger.info("Token refreshed successfully.")
        else:
            logger.info("Starting OAuth consent flow...")
            flow = InstalledAppFlow.from_client_config({
                "installed": {
                    "client_id": st.secrets["gmail_client_id"],
                    "project_id": st.secrets["gmail_project_id"],
                    "auth_uri": st.secrets["gmail_auth_uri"],
                    "token_uri": st.secrets["gmail_token_uri"],
                    "auth_provider_x509_cert_url": st.secrets["gmail_auth_provider_cert_url"],
                    "client_secret": st.secrets["gmail_client_secret"],
                    "redirect_uris": ["http://localhost:*"]
                }
            }, SCOPES)

            try:
                creds = flow.run_local_server(
                    port=0,  # Automatically chooses an available port
                    authorization_prompt_message="Please visit this URL: {url}",
                    success_message="Authentication complete! You may close this window.",
                    open_browser=False  # Avoids browser issues
                )
                logger.info("OAuth flow completed successfully.")
            except Exception as e:
                logger.error("Error during OAuth flow.", exc_info=True)
                st.error("Authentication failed. Check logs for details.")
                raise e

        # Save the token
        with open(token_file, 'wb') as token:
            pickle.dump(creds, token)
            logger.info("Token saved to file.")

    # Initialize Gmail API client
    try:
        service = build('gmail', 'v1', credentials=creds)
        logger.info("Gmail API client initialized successfully.")
        return service
    except Exception as e:
        logger.error("Failed to initialize Gmail API client.", exc_info=True)
        st.error("Failed to initialize Gmail API client. Please check your credentials and try again.")
        raise e

# Fetch emails
def fetch_emails(service, query="label:inbox"):
    """Fetches emails from Gmail using the specified query."""
    logger.info(f"Fetching emails with query: {query}")
    try:
        results = service.users().messages().list(userId='me', q=query).execute()
        messages = results.get('messages', [])
        email_data = []

        if not messages:
            st.info("No emails found.")
            logger.info("No emails found.")
            return email_data

        for msg in messages[:5]:  # Fetch only the first 5 emails
            email = service.users().messages().get(userId='me', id=msg['id']).execute()
            snippet = email.get('snippet', 'No content')  # Extract email snippet
            email_data.append({
                'id': msg['id'],
                'snippet': snippet,
                'internalDate': email.get('internalDate'),
                'payload': email.get('payload', {}).get('headers', [])
            })
        logger.info(f"Fetched {len(email_data)} emails successfully.")
        return email_data
    except Exception as e:
        logger.error("Error fetching emails.", exc_info=True)
        st.error("Failed to fetch emails. Check logs for details.")
        raise e

# Streamlit app
st.title("Gmail Dashboard")
st.write("A dashboard to view and analyze your Gmail data.")

# Button to trigger email fetching
if st.button("Authenticate and Fetch Emails"):
    try:
        logger.info("Button clicked: Authenticate and Fetch Emails")
        service = authenticate_gmail()  # Authenticate Gmail API
        emails = fetch_emails(service)  # Fetch emails
        if emails:
            st.write("Fetched Emails:")
            for email in emails:
                st.write(f"**ID**: {email['id']}")
                st.write(f"**Snippet**: {email['snippet']}")
                st.write("---")
    except Exception as e:
        logger.error("Error during email fetching.", exc_info=True)

# Footer
st.write("Powered by Gmail API and Streamlit.")
