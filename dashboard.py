import os
import logging
import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import pickle
from google.auth.transport.requests import Request

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("app.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Define Gmail API Scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Authorized test users
AUTHORIZED_TEST_USERS = ["sortsyai@gmail.com", "adammsutton@gmail.com"]

# Function to clear the log file
def clear_log():
    with open("app.log", "w"):
        pass

# Authenticate Gmail API
def authenticate_gmail(user_email):
    logger.info("Starting Gmail authentication for user: %s", user_email)
    token_file = f'token_{user_email}.pickle'
    creds = None

    # Check if a token already exists
    if os.path.exists(token_file):
        logger.info("Loading existing token for user: %s", user_email)
        with open(token_file, 'rb') as token:
            creds = pickle.load(token)

    # If no valid token, initiate OAuth flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logger.info("Refreshing expired token...")
            creds.refresh(Request())
        else:
            logger.info("Initiating OAuth flow...")
            client_config = {
                "web": {
                    "client_id": st.secrets["web"]["client_id"],
                    "project_id": st.secrets["web"]["project_id"],
                    "auth_uri": st.secrets["web"]["auth_uri"],
                    "token_uri": st.secrets["web"]["token_uri"],
                    "auth_provider_x509_cert_url": st.secrets["web"]["auth_provider_x509_cert_url"],
                    "client_secret": st.secrets["web"]["client_secret"],
                    "redirect_uris": st.secrets["web"]["redirect_uris"]
                }
            }
            flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
            creds = flow.run_local_server(port=8080)  # Avoid conflicts with default port
            logger.info("OAuth flow completed successfully.")

        # Save the token for future use
        with open(token_file, 'wb') as token:
            pickle.dump(creds, token)
            logger.info("Token saved successfully for user: %s", user_email)

    # Build Gmail API client
    try:
        service = build('gmail', 'v1', credentials=creds)
        logger.info("Gmail API client initialized successfully for user: %s", user_email)
        return service
    except Exception as e:
        logger.error("Error initializing Gmail API client:", exc_info=True)
        raise e

# Fetch Emails
def fetch_emails(service, query="label:inbox"):
    logger.info("Fetching emails with query: %s", query)
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
        st.error("Failed to fetch emails.")
        return []

# Streamlit App
st.title("Gmail Dashboard")
st.write("A dashboard to view and analyze your Gmail data.")

# Email input for user selection
selected_email = st.text_input("Enter your email (test users only):")

if selected_email:
    if selected_email not in AUTHORIZED_TEST_USERS:
        st.error(f"Email {selected_email} is not authorized. Please use a valid test email.")
    else:
        # Button to trigger email fetching
        if st.button("Authenticate and Fetch Emails"):
            try:
                clear_log()
                logger.info("Button clicked: Authenticate and Fetch Emails")
                service = authenticate_gmail(selected_email)  # Authenticate Gmail API
                emails = fetch_emails(service)  # Fetch emails
                if emails:
                    st.write("Fetched Emails:")
                    for email in emails:
                        st.write(f"**ID**: {email['id']}")
                        st.write(f"**Snippet**: {email['snippet']}")
                        st.write("---")
            except Exception as e:
                st.error(f"An error occurred during authentication: {e}")
                logger.error("An error occurred during authentication:", exc_info=True)

# Footer
st.write("Powered by Gmail API and Streamlit.")
