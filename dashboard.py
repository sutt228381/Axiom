import os
import logging
import pickle
import streamlit as st
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("app.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# Set environment for Streamlit
os.environ["STREAMLIT_SERVER_HEADLESS"] = "true"

# Authorized test users (case-insensitive check)
AUTHORIZED_TEST_USERS = ["sortsyai@gmail.com", "adammsutton@gmail.com"]

# Gmail API scope and secrets
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
TOKEN_FILE = "token.pickle"
SECRETS_FILE = "client_secrets.json"
REDIRECT_URI = "https://axiomgit-dppnbnhmqnccrv4xcjm3r3.streamlit.app/"

# Gmail authentication
def authenticate_gmail():
    logger.info("Starting Gmail authentication...")
    creds = None

    # Check for an existing token
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'rb') as token:
            creds = pickle.load(token)

    # If no valid token, proceed with OAuth flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            logger.info("Initiating OAuth flow...")
            flow = Flow.from_client_secrets_file(
                SECRETS_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI
            )
            auth_url, _ = flow.authorization_url(prompt='consent')
            st.write(f"Please authenticate by visiting [this link]({auth_url})")
            auth_code = st.text_input("Enter the authorization code here:")
            if auth_code:
                try:
                    flow.fetch_token(code=auth_code)
                    creds = flow.credentials
                    # Save the token for future use
                    with open(TOKEN_FILE, 'wb') as token:
                        pickle.dump(creds, token)
                except Exception as e:
                    st.error(f"Authentication failed: {e}")
                    st.stop()

    # Initialize the Gmail API client
    try:
        service = build('gmail', 'v1', credentials=creds)
        logger.info("Gmail API client initialized successfully.")
        return service
    except Exception as e:
        logger.error("Failed to initialize Gmail API client.", exc_info=True)
        raise e

# Fetch emails
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
                'payload': email.get('payload', {}).get('headers', [])
            })
        return email_data
    except Exception as e:
        logger.error("Error fetching emails", exc_info=True)
        st.error("Failed to fetch emails.")
        return []

# Streamlit app
def main():
    st.title("Gmail Dashboard")
    st.write("A dashboard to view and analyze your Gmail data.")

    # Prompt user to enter email address
    entered_email = st.text_input("Enter your email address to authenticate:")
    if entered_email:
        # Case-insensitive check for authorized test users
        if entered_email.lower() not in [email.lower() for email in AUTHORIZED_TEST_USERS]:
            st.error("Email not authorized. Please use a valid test email.")
            st.stop()

    # Authenticate and fetch emails
    if st.button("Authenticate and Fetch Emails"):
        logger.info("Button clicked: Authenticate and Fetch Emails")
        try:
            service = authenticate_gmail()
            st.write("Fetching emails...")
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

if __name__ == "__main__":
    main()
