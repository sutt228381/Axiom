import os
import pickle
import logging
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import streamlit as st

# Logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log"),  # Log to a file
        logging.StreamHandler(),         # Stream logs to the console
    ],
)
logger = logging.getLogger(__name__)

# Set environment variables
os.environ["GOOGLE_CLOUD_PROJECT"] = "concise-rex-442402-b5"
os.environ["NO_GCE_CHECK"] = "true"

# Gmail API scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Function to authenticate Gmail API
def authenticate_gmail():
    logger.info("Starting Gmail authentication...")
    token_file = 'token.pickle'
    creds = None

    # Check if a token file exists
    if os.path.exists(token_file):
        logger.info("Loading existing token...")
        with open(token_file, 'rb') as token:
            creds = pickle.load(token)

    # If no valid credentials, start OAuth flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logger.info("Refreshing expired token...")
            creds.refresh(Request())
        else:
            logger.info("Starting OAuth consent flow...")
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            try:
                creds = flow.run_local_server(
                    host="0.0.0.0",
                    port=8080,
                    authorization_prompt_message="Please visit this URL: {url}",
                    success_message="Authentication successful! You may close this window.",
                    open_browser=True,
                )
                logger.info("OAuth flow completed successfully.")
            except Exception as e:
                logger.error("Error during OAuth flow.", exc_info=True)
                raise e

        # Save the token for future use
        with open(token_file, 'wb') as token:
            pickle.dump(creds, token)
            logger.info("Token saved successfully.")

    # Initialize Gmail API client
    try:
        service = build('gmail', 'v1', credentials=creds)
        logger.info("Gmail API client initialized successfully.")
        return service
    except Exception as e:
        logger.error("Error initializing Gmail API client.", exc_info=True)
        raise e

# Function to fetch emails
def fetch_emails(service, query="label:inbox"):
    logger.info(f"Fetching emails with query: {query}")
    try:
        results = service.users().messages().list(userId='me', q=query).execute()
        messages = results.get('messages', [])
        email_data = []
        for msg in messages[:5]:  # Fetch only the first 5 emails
            email = service.users().messages().get(userId='me', id=msg['id']).execute()
            snippet = email.get('snippet', 'No content')  # Extract email snippet
            email_data.append({
                'id': msg['id'],
                'snippet': snippet,
                'internalDate': email.get('internalDate'),
                'payload': email.get('payload', {}).get('headers', []),
            })
        return email_data
    except Exception as e:
        logger.error("Error fetching emails.", exc_info=True)
        raise e

# Streamlit app UI
st.title("Gmail Dashboard")
st.write("A dashboard to view and analyze your Gmail data.")

# Button to fetch emails
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
            st.write("No emails found.")
    except Exception as e:
        st.error(f"An error occurred: {e}")

# Footer
st.write("Powered by Gmail API and Streamlit.")
