import os
import logging
import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import pickle
from google.auth.transport.requests import Request

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

# Set environment for Streamlit
os.environ["STREAMLIT_SERVER_HEADLESS"] = "false"  # Use "true" for headless mode
os.environ["BROWSER"] = "chrome"  # Set this to the browser you want to use

# Define Gmail API Scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticate_gmail():
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
        else:
            logger.info("Initiating OAuth flow...")
            try:
                flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)  # Open OAuth consent screen
                logger.info("OAuth flow completed successfully.")
            except Exception as e:
                logger.error("Error during OAuth flow:", exc_info=True)
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
        raise e

# Fetch Emails
def fetch_emails(service, query="label:inbox"):
    # Search for emails based on the query
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
    except Exception as e:
        st.error(f"An error occurred: {e}")

# Footer
st.write("Powered by Gmail API and Streamlit.")
