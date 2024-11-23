import os
import logging
import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import pickle
from google.auth.transport.requests import Request

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log"),  # Log to a file
        logging.StreamHandler()         # Log to the terminal
    ]
)
logger = logging.getLogger(__name__)

# Set Google Cloud Project ID
os.environ["GOOGLE_CLOUD_PROJECT"] = st.secrets["gmail_project_id"]
os.environ["NO_GCE_CHECK"] = "true"  # Suppress Compute Engine warnings
logger.info(f"Google Cloud Project: {os.environ.get('GOOGLE_CLOUD_PROJECT')}")

# Define Gmail API scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Authenticate Gmail API
def authenticate_gmail():
    token_file = 'token.pickle'
    creds = None

    # Load existing token if available
    if os.path.exists(token_file):
        logger.info("Loading existing token...")
        with open(token_file, 'rb') as token:
            creds = pickle.load(token)

    # If no valid token, initiate OAuth flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logger.info("Refreshing expired token...")
            creds.refresh(Request())
        else:
            logger.info("Starting OAuth consent flow...")
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=8080)  # Using port 8080
            logger.info("OAuth flow completed successfully.")

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
        raise e

# Fetch Emails
def fetch_emails(service, query="label:inbox"):
    logger.info(f"Fetching emails with query: {query}")
    try:
        results = service.users().messages().list(userId='me', q=query).execute()
        messages = results.get('messages', [])
        email_data = []
        if not messages:
            st.write("No emails found.")
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
        return email_data
    except Exception as e:
        logger.error("Error fetching emails:", exc_info=True)
        st.error("An error occurred while fetching emails.")

# Streamlit App
st.title("Gmail Dashboard")
st.write("A dashboard to view and analyze your Gmail data.")

# Button to trigger email fetching
if st.button("Authenticate and Fetch Emails"):
    try:
        logger.info("Button clicked: Authenticate and Fetch Emails")
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
    except Exception as e:
        logger.error("Error during email fetching.", exc_info=True)
        st.error("An error occurred. Please check the logs.")

# Footer
st.write("Powered by Gmail API and Streamlit.")
