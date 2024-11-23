import os
import logging
import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import pickle
from google.auth.transport.requests import Request
from logging.handlers import RotatingFileHandler

# Function to clear the log file
def clear_log_file():
    """Clear the log file at the start of the app."""
    try:
        with open("app.log", "w") as log_file:
            log_file.truncate()
        logger.info("Log file cleared at app start.")
    except Exception as e:
        st.error(f"Error clearing log file: {e}")
        logger.error(f"Error clearing log file: {e}")

# Configure logging with rotation
logging.basicConfig(
    level=logging.INFO,  # Set to INFO or DEBUG for more details
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        RotatingFileHandler("app.log", maxBytes=5000000, backupCount=3),  # Ensure the file is created
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

# Gmail API Scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

st.write(f"Current working directory: {os.getcwd()}")  # Debug current working directory
st.write("Step 1: App started")

def authenticate_gmail():
    """Authenticate with the Gmail API using headless flow."""
    logger.info("Starting Gmail authentication...")
    token_file = 'token.pickle'
    creds = None

    # Check for existing token
    if os.path.exists(token_file):
        logger.info("Loading existing token...")
        with open(token_file, 'rb') as token:
            creds = pickle.load(token)
        st.write("Step 3: Loaded existing token")

    # If no valid token, initiate OAuth flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logger.info("Refreshing expired token...")
            creds.refresh(Request())
            st.write("Step 4: Token refreshed")
        else:
            logger.info("Initiating OAuth flow...")
            try:
                # Prepare the credentials object
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
                # Set up the OAuth flow
                flow = InstalledAppFlow.from_client_config(credentials, SCOPES)
                flow.redirect_uri = credentials["installed"]["redirect_uris"][0]
                auth_url, _ = flow.authorization_url(prompt='consent')
                st.write("Please go to this URL to authenticate:")
                st.write(auth_url)

                # Input box for authorization code
                auth_code = st.text_input("Authorization Code", key="auth_code")
                if auth_code:
                    creds = flow.fetch_token(code=auth_code)
                    st.write("Step 6: OAuth flow completed")
                    logger.info("OAuth flow completed successfully.")
            except Exception as e:
                logger.error("Error during OAuth flow:", exc_info=True)
                st.error("Failed to complete OAuth authentication. Please try again.")
                raise e

        # Save the token
        with open(token_file, 'wb') as token:
            pickle.dump(creds, token)
            st.write("Step 7: Token saved successfully")
            logger.info("Token saved successfully.")

    # Build Gmail API client
    try:
        service = build('gmail', 'v1', credentials=creds)
        st.write("Step 8: Gmail API client initialized")
        logger.info("Gmail API client initialized successfully.")
        return service
    except Exception as e:
        logger.error("Error initializing Gmail API client:", exc_info=True)
        st.error("Failed to initialize Gmail API client. Please check your credentials and try again.")
        raise e

def fetch_emails(service, query="", limit=5):
    """Fetch a limited number of emails based on a query."""
    try:
        st.write("Step 9: Fetching emails")
        logger.info("Fetching emails with query: %s", query)

        # Call Gmail API to list messages
        results = service.users().messages().list(userId='me', q=query).execute()
        logger.info("Gmail API response: %s", results)  # Log the full response for debugging

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
        st.write("Step 10: Emails fetched successfully")
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
        service = authenticate_gmail()
        st.write("Fetching emails...")
        emails = fetch_emails(service, query="", limit=5)  # Fetch a maximum of 5 emails
        if emails:
            st.success("Fetched Emails:")
            for email in emails:
                st.write(f"**ID**: {email['id']}")
                st.write(f"**Snippet**: {email['snippet']}")
                st.write("---")
        else:
            st.warning("No emails found. Try sending test emails to your account.")

    except Exception as e:
        st.error(f"An error occurred: {e}")
        logger.error("Error during email fetching or display: ", exc_info=True)

if st.button("Show Logs"):
    display_logs()

st.write("Powered by Gmail API and Streamlit.")
