import os
import logging
import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import pickle
from google.auth.transport.requests import Request

# Suppress Compute Engine Metadata warnings
os.environ["NO_GCE_CHECK"] = "true"
os.environ["GOOGLE_CLOUD_PROJECT"] = "placeholder-project"

# Gmail API Scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Logging setup
def setup_logger():
    """Sets up logging with a rotating file handler."""
    log_file = "app.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    logger = logging.getLogger(__name__)
    try:
        with open(log_file, "a") as log_test:
            log_test.write("Log file initialized.\n")
        logger.info("Log file initialized successfully.")
    except Exception as e:
        st.error(f"Cannot write to log file: {e}")
        logger.error(f"Cannot write to log file: {e}")
    return logger

logger = setup_logger()

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
                    "redirect_uris": ["http://localhost:8080/"]
                }
            }, SCOPES)

            try:
                creds = flow.run_local_server(
                    port=8080,
                    authorization_prompt_message="Please visit this URL: {url}",
                    success_message="Authentication complete! You may close this window.",
                    open_browser=False
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

def fetch_emails(service, query="", limit=5):
    """Fetch emails from Gmail API."""
    try:
        logger.info(f"Fetching emails with query: {query}")
        results = service.users().messages().list(userId='me', q=query).execute()
        st.write("Raw Gmail API Response:")
        st.json(results)
        logger.info(f"Raw response: {results}")
        messages = results.get('messages', [])
        if not messages:
            st.warning("No emails found.")
            logger.info("No emails found in Gmail response.")
            return []

        email_data = []
        for msg in messages[:limit]:
            email = service.users().messages().get(userId='me', id=msg['id']).execute()
            snippet = email.get('snippet', 'No content')
            email_data.append({"id": msg['id'], "snippet": snippet})
        logger.info(f"Fetched emails: {email_data}")
        return email_data
    except Exception as e:
        logger.error("Error fetching emails", exc_info=True)
        st.error("Failed to fetch emails. Please check your Gmail permissions and try again.")
        return []

# Streamlit App UI
st.title("Gmail Dashboard")
st.write("A dashboard to view and analyze your Gmail data.")

if st.button("Authenticate and Fetch Emails"):
    try:
        st.write("Authenticating with Gmail...")
        service = authenticate_gmail()
        emails = fetch_emails(service, query="label:inbox", limit=5)
        if emails:
            st.success("Fetched Emails:")
            for email in emails:
                st.write(f"**ID**: {email['id']}")
                st.write(f"**Snippet**: {email['snippet']}")
                st.write("---")
        else:
            st.warning("No emails found.")
    except Exception as e:
        st.error(f"An error occurred: {e}")
        logger.error("Error during email fetching.", exc_info=True)

st.write("Powered by Gmail API and Streamlit.")
