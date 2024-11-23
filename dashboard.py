import os
import logging
import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import pickle
from google.auth.transport.requests import Request
from logging.handlers import RotatingFileHandler

# Suppress Compute Engine metadata warnings
os.environ["NO_GCE_CHECK"] = "true"

# Gmail API Scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Clear and set up logging
def clear_log_file():
    """Clear the log file at the start of the app."""
    with open("app.log", "w") as log_file:
        log_file.truncate()

clear_log_file()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        RotatingFileHandler("app.log", maxBytes=5000000, backupCount=3),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Test log file creation
try:
    with open("app.log", "a") as test_log:
        test_log.write("Log file initialized.\n")
    logger.info("Log file initialized successfully.")
except Exception as e:
    st.error(f"Cannot write to log file: {e}")
    logger.error(f"Cannot write to log file: {e}")

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
            logger.info("Token loaded successfully.")

    # If no valid token, initiate OAuth flow
    if not creds or not creds.valid:
        logger.info("No valid token found. Proceeding with OAuth flow...")
        if creds and creds.expired and creds.refresh_token:
            logger.info("Refreshing expired token...")
            creds.refresh(Request())
            logger.info("Token refreshed successfully.")
        else:
            logger.info("Starting OAuth consent flow...")
            try:
                credentials = {
                    "installed": {
                        "client_id": st.secrets["gmail_client_id"],
                        "project_id": st.secrets["gmail_project_id"],
                        "auth_uri": st.secrets["gmail_auth_uri"],
                        "token_uri": st.secrets["gmail_token_uri"],
                        "auth_provider_x509_cert_url": st.secrets["gmail_auth_provider_cert_url"],
                        "client_secret": st.secrets["gmail_client_secret"],
                        "redirect_uris": [st.secrets["gmail_redirect_uri"]]
                    }
                }
                flow = InstalledAppFlow.from_client_config(credentials, SCOPES)
                flow.redirect_uri = credentials["installed"]["redirect_uris"][0]
                auth_url, _ = flow.authorization_url(prompt='consent')
                logger.info("OAuth URL generated successfully.")
                st.write("Authenticate by visiting this URL:")
                st.write(auth_url)

                auth_code = st.text_input("Authorization Code", key="auth_code")
                if auth_code:
                    logger.info("Authorization code received. Exchanging for token...")
                    creds = flow.fetch_token(code=auth_code)
                    logger.info("Token obtained successfully.")
            except Exception as e:
                logger.error("Error during OAuth flow.", exc_info=True)
                st.error("Authentication failed. Check logs for details.")
                raise e

        # Save the token
        with open(token_file, 'wb') as token:
            pickle.dump(creds, token)
            logger.info("Token saved to file.")

    # Build Gmail API client
    try:
        logger.info("Initializing Gmail API client...")
        service = build('gmail', 'v1', credentials=creds)
        logger.info("Gmail API client initialized successfully.")
        st.write("Step 8: Gmail API client initialized")  # Debugging output
        return service
    except Exception as e:
        logger.error("Failed to initialize Gmail API client.", exc_info=True)
        st.error("Failed to initialize Gmail API client. Please check your credentials and try again.")
        raise e

def fetch_emails(service, query="", limit=5):
    """Fetch a limited number of emails based on a query."""
    try:
        logger.info("Fetching emails with query: %s", query)
        st.write(f"Using query: {query}")

        # Call Gmail API to list messages
        results = service.users().messages().list(userId='me', q=query).execute()
        st.write("Raw Gmail API Response:")
        st.json(results)  # Display the full API response for debugging
        logger.info("Raw Gmail API response: %s", results)

        # Extract messages
        messages = results.get('messages', [])
        email_data = []
        if not messages:
            st.write("No emails found.")
            logger.info("No emails found in Gmail response.")
            return email_data

        # Fetch detailed information for each message
        for msg in messages[:limit]:
            email = service.users().messages().get(userId='me', id=msg['id']).execute()
            snippet = email.get('snippet', 'No content')  # Extract snippet
            email_data.append({"id": msg['id'], "snippet": snippet})
        logger.info("Fetched emails: %s", email_data)
        return email_data

    except Exception as e:
        logger.error("Error fetching emails: %s", str(e), exc_info=True)
        st.error("Failed to fetch emails. Please check your Gmail permissions and try again.")
        raise e

def display_logs():
    """Display only the last 100 lines of the log file in the Streamlit UI."""
    log_file_path = "app.log"  # Ensure this matches your log file path
    st.write(f"Checking for log file: {log_file_path}")

    if os.path.exists(log_file_path):
        st.write(f"Log file exists: {log_file_path}")
        with open(log_file_path, "r") as log_file:
            logs = log_file.readlines()
            if logs:
                st.text("".join(logs[-100:]))  # Show only the last 100 lines
            else:
                st.write("Log file is empty.")
    else:
        st.write("Log file not found.")

# Streamlit App
st.title("Gmail Dashboard")
st.write("A dashboard to view and analyze your Gmail data.")

if st.button("Authenticate and Fetch Emails"):
    try:
        st.write("Authenticating with Gmail...")
        logger.info("Button clicked: Authenticate and Fetch Emails")
        service = authenticate_gmail()
        if not service:
            st.error("Failed to initialize Gmail API service. Check logs for details.")
            logger.error("Gmail API service was not initialized.")
            raise ValueError("Service initialization failed")

        st.write("Fetching emails...")
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
        logger.error("Error occurred during email fetching.", exc_info=True)

if st.button("Show Logs"):
    display_logs()

st.write("Powered by Gmail API and Streamlit.")
