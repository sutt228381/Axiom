import os
import logging
import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import pickle
from google.auth.transport.requests import Request

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Gmail API Scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

st.write("Step 1: App started")

def authenticate_gmail():
    """Authenticate with the Gmail API using headless flow."""
    st.write("Step 2: Entering authenticate_gmail()")
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
                credentials = {
                    "installed": {
                        "client_id": st.secrets["gmail_client_id"],
                        "project_id": st.secrets["gmail_project_id"],
                        "auth_uri": st.secrets["gmail_auth_uri"],
                        "token_uri": st.secrets["gmail_token_uri"],
                        "auth_provider_x509_cert_url": st.secrets["gmail_auth_provider_x509_cert_url"],
                        "client_secret": st.secrets["gmail_client_secret"],
                        "redirect_uris": [st.secrets["gmail_redirect_uris"]]
                    }
                }
                flow = InstalledAppFlow.from_client_config(credentials, SCOPES)
                auth_url, _ = flow.authorization_url(prompt='consent')
                st.write("Step 5: Authorization URL generated")
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

def fetch_emails(service, query="label:inbox"):
    """Fetch emails based on a query."""
    try:
        st.write("Step 9: Fetching emails")
        logger.info("Fetching emails with query: %s", query)
        results = service.users().messages().list(userId='me', q=query).execute()
        messages = results.get('messages', [])
        email_data = []
        if not messages:
            st.write("No emails found.")
            logger.info("No emails found.")
            return email_data
        for msg in messages[:5]:
            email = service.users().messages().get(userId='me', id=msg['id']).execute()
            snippet = email.get('snippet', 'No content')
            email_data.append({"id": msg['id'], "snippet": snippet})
        st.write("Step 10: Emails fetched successfully")
        return email_data
    except Exception as e:
        logger.error("Error fetching emails:", exc_info=True)
        st.error("Failed to fetch emails. Please try again.")
        raise e

def display_logs():
    """Display logs in the Streamlit UI."""
    if os.path.exists("app.log"):
        with open("app.log", "r") as log_file:
            st.text(log_file.read())

# Streamlit App
st.title("Gmail Dashboard")
st.write("A dashboard to view and analyze your Gmail data.")

if st.button("Fetch Emails"):
    try:
        service = authenticate_gmail()
        emails = fetch_emails(service)
        if emails:
            for email in emails:
                st.write(f"**ID**: {email['id']}")
                st.write(f"**Snippet**: {email['snippet']}")
                st.write("---")
        else:
            st.write("No emails to display.")
    except Exception as e:
        st.error(f"An error occurred: {e}")

if st.button("Show Logs"):
    display_logs()

st.write("Powered by Gmail API and Streamlit.")
