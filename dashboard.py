import os
import logging
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import streamlit as st

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
logger = logging.getLogger(__name__)

# Define the Gmail API scope
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Ensure project environment variables are set
os.environ["GOOGLE_CLOUD_PROJECT"] = st.secrets["web"]["project_id"]

# Authenticate with Gmail API
def authenticate_gmail():
    logger.info("Starting Gmail authentication...")
    token_file = "token.json"
    creds = None

    # Check if a token already exists
    if os.path.exists(token_file):
        logger.info("Loading existing token...")
        with open(token_file, "r") as token:
            creds = Credentials.from_authorized_user_file(token_file, SCOPES)

    # If no valid token, initiate OAuth flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logger.info("Refreshing expired token...")
            creds.refresh(Request())
        else:
            logger.info("Initiating OAuth flow...")
            try:
                flow = InstalledAppFlow.from_client_secrets_file(
                    "client_secrets.json", SCOPES
                )
                auth_url, _ = flow.authorization_url(prompt="consent")
                st.write("Please authenticate using the following link:")
                st.write(auth_url)

                # Input field for authentication code
                auth_code = st.text_input("Enter the authorization code:")
                if auth_code:
                    creds = flow.fetch_token(code=auth_code)
                    logger.info("OAuth flow completed successfully.")
            except Exception as e:
                logger.error("Error during OAuth flow.", exc_info=True)
                st.error(f"An error occurred during OAuth flow: {e}")
                return None

        # Save the token for future use
        with open(token_file, "w") as token:
            token.write(creds.to_json())
            logger.info("Token saved successfully.")

    # Build Gmail API client
    try:
        service = build("gmail", "v1", credentials=creds)
        logger.info("Gmail API client initialized successfully.")
        return service
    except Exception as e:
        logger.error("Error initializing Gmail API client.", exc_info=True)
        st.error(f"An error occurred initializing Gmail API client: {e}")
        return None

# Fetch emails
def fetch_emails(service):
    logger.info("Fetching emails...")
    try:
        results = service.users().messages().list(userId="me", q="label:inbox").execute()
        messages = results.get("messages", [])
        if not messages:
            st.write("No emails found.")
            return
        st.write("Fetched Emails:")
        for message in messages[:5]:  # Limit to the first 5 emails
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            st.write(f"Snippet: {msg.get('snippet', 'No content')}")
    except Exception as e:
        logger.error("Error fetching emails.", exc_info=True)
        st.error(f"An error occurred while fetching emails: {e}")

# Streamlit UI
st.title("Gmail Dashboard")
st.write("Authenticate and view your Gmail inbox snippets.")

if st.button("Authenticate and Fetch Emails"):
    service = authenticate_gmail()
    if service:
        fetch_emails(service)
