import os
import logging
import pickle
from logging.handlers import RotatingFileHandler
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import streamlit as st

# Constants
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
TOKEN_FILE = "token.pickle"
LOG_FILE = "app.log"

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        RotatingFileHandler(LOG_FILE, maxBytes=5000000, backupCount=3),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

# Set Google Cloud Project explicitly
os.environ["GOOGLE_CLOUD_PROJECT"] = "concise-rex-442402-b5"
logger.info(f"Google Cloud Project: {os.environ['GOOGLE_CLOUD_PROJECT']}")


def clear_log_file():
    """Clear the log file on each run."""
    with open(LOG_FILE, "w"):
        pass


clear_log_file()
logger.info("Log file initialized successfully.")


def authenticate_gmail():
    """Authenticate Gmail API using OAuth."""
    logger.info("Starting Gmail authentication...")
    creds = None

    # Check if token exists
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "rb") as token:
            creds = pickle.load(token)
        logger.info("Loaded existing token.")
    else:
        logger.info("No valid token found. Starting OAuth consent flow...")

    try:
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
                logger.info("Token refreshed.")
            else:
                # Load credentials from secrets
                secrets = st.secrets["web"]
                credentials_info = {
                    "installed": {
                        "client_id": secrets["client_id"],
                        "client_secret": secrets["client_secret"],
                        "auth_uri": secrets["auth_uri"],
                        "token_uri": secrets["token_uri"],
                        "redirect_uris": secrets["redirect_uris"],
                    }
                }
                flow = InstalledAppFlow.from_client_config(credentials_info, SCOPES)

                # Attempt local server flow first
                try:
                    creds = flow.run_local_server(port=8080)
                    logger.info("Local server flow completed.")
                except OSError as e:
                    logger.warning(
                        "Local server flow failed. Falling back to manual flow."
                    )
                    creds = flow.run_console()
                    logger.info("Console flow completed.")

            # Save the credentials for the next run
            with open(TOKEN_FILE, "wb") as token:
                pickle.dump(creds, token)
                logger.info("Token saved successfully.")
    except Exception as e:
        logger.error("Error during Gmail authentication:", exc_info=True)
        raise e

    return build("gmail", "v1", credentials=creds)


def fetch_emails(service, query="label:inbox"):
    """Fetch emails using the Gmail API."""
    logger.info(f"Fetching emails with query: {query}")
    try:
        results = service.users().messages().list(userId="me", q=query).execute()
        messages = results.get("messages", [])
        email_data = []

        if not messages:
            logger.info("No emails found.")
            st.write("No emails found.")
            return email_data

        for msg in messages[:5]:  # Fetch only the first 5 emails
            email = service.users().messages().get(userId="me", id=msg["id"]).execute()
            snippet = email.get("snippet", "No content")  # Extract email snippet
            email_data.append(
                {
                    "id": msg["id"],
                    "snippet": snippet,
                    "internalDate": email.get("internalDate"),
                }
            )
        return email_data
    except Exception as e:
        logger.error("Error fetching emails:", exc_info=True)
        st.error(f"An error occurred while fetching emails: {e}")
        return []


# Streamlit App
st.title("Gmail Dashboard")
st.write("A dashboard to view and analyze your Gmail data.")

if st.button("Authenticate and Fetch Emails"):
    logger.info("Button clicked: Authenticate and Fetch Emails")
    try:
        service = authenticate_gmail()
        emails = fetch_emails(service)
        if emails:
            st.write("Fetched Emails:")
            for email in emails:
                st.write(f"**ID**: {email['id']}")
                st.write(f"**Snippet**: {email['snippet']}")
                st.write("---")
        else:
            st.write("No emails to display.")
    except Exception as e:
        st.error(f"An error occurred during authentication: {e}")

st.write("Powered by Gmail API and Streamlit.")
