import os
import logging
import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import pickle

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Explicitly set Google Cloud Project
os.environ["GOOGLE_CLOUD_PROJECT"] = "concise-rex-442402-b5"

# Authorized test users (case-insensitive)
AUTHORIZED_TEST_USERS = ["sortsyai@gmail.com", "adammsutton@gmail.com"]

# Gmail API Scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Function to authenticate Gmail API
def authenticate_gmail():
    logger.info("Starting Gmail authentication...")
    token_file = 'token.pickle'
    creds = None

    # Load existing token
    if os.path.exists(token_file):
        logger.info("Loading existing token...")
        with open(token_file, 'rb') as token:
            creds = pickle.load(token)

    # OAuth flow if no valid token
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logger.info("Refreshing expired token...")
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('client_secrets.json', SCOPES)
            logger.info("Starting OAuth consent flow...")
            creds = flow.run_local_server(port=8080, open_browser=False)  # Open consent page

        # Save token for future use
        with open(token_file, 'wb') as token:
            pickle.dump(creds, token)
            logger.info("Token saved successfully.")

    return build('gmail', 'v1', credentials=creds)

# Function to fetch emails
def fetch_emails(service, query="label:inbox"):
    logger.info(f"Fetching emails with query: {query}")
    try:
        results = service.users().messages().list(userId='me', q=query).execute()
        messages = results.get('messages', [])
        email_data = []
        for msg in messages[:5]:  # Fetch first 5 emails
            email = service.users().messages().get(userId='me', id=msg['id']).execute()
            snippet = email.get('snippet', 'No content')
            email_data.append({
                'id': msg['id'],
                'snippet': snippet,
            })
        return email_data
    except Exception as e:
        logger.error("Error fetching emails:", exc_info=True)
        st.error(f"An error occurred while fetching emails: {e}")
        return []

# Streamlit UI
st.title("Gmail Dashboard")
st.write("Fetch and view emails using Gmail API.")

# User email input
user_email = st.text_input("Enter your email address:")
if user_email:
    if user_email.lower() not in [email.lower() for email in AUTHORIZED_TEST_USERS]:
        st.error("Email is not authorized. Please use a valid test email.")
    else:
        if st.button("Authenticate and Fetch Emails"):
            try:
                service = authenticate_gmail()
                emails = fetch_emails(service)
                if emails:
                    st.write("Fetched Emails:")
                    for email in emails:
                        st.write(f"**ID:** {email['id']}")
                        st.write(f"**Snippet:** {email['snippet']}")
                        st.write("---")
                else:
                    st.write("No emails found.")
            except Exception as e:
                st.error(f"An error occurred during authentication: {e}")
