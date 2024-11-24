import os
import logging
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import streamlit as st

# Set up logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Streamlit Secrets
CLIENT_ID = st.secrets["web"]["client_id"]
PROJECT_ID = st.secrets["web"]["project_id"]
CLIENT_SECRET = st.secrets["web"]["client_secret"]
REDIRECT_URI = st.secrets["web"]["redirect_uris"][0]
AUTH_URI = st.secrets["web"]["auth_uri"]
TOKEN_URI = st.secrets["web"]["token_uri"]

def authenticate_gmail():
    """Authenticate Gmail API for Streamlit Cloud."""
    logger.info("Starting Gmail authentication...")
    credentials_file = {
        "installed": {
            "client_id": CLIENT_ID,
            "project_id": PROJECT_ID,
            "auth_uri": AUTH_URI,
            "token_uri": TOKEN_URI,
            "client_secret": CLIENT_SECRET,
            "redirect_uris": [REDIRECT_URI]
        }
    }

    flow = Flow.from_client_config(credentials_file, SCOPES)
    flow.redirect_uri = REDIRECT_URI

    # Generate authorization URL
    auth_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    logger.info(f"Redirecting user to: {auth_url}")

    st.write("Click the link below to authenticate:")
    st.markdown(f"[Authenticate with Gmail]({auth_url})")

    # Wait for user to input authorization code
    code = st.text_input("Paste the authorization code here:", key="auth_code")
    if code:
        try:
            flow.fetch_token(code=code)
            creds = flow.credentials
            logger.info("Authentication successful. Initializing Gmail API client...")
            return build('gmail', 'v1', credentials=creds)
        except Exception as e:
            logger.error(f"Error during authentication: {e}")
            st.error(f"An error occurred during authentication: {e}")

    return None

def fetch_emails(service, query="label:inbox"):
    """Fetch the latest emails."""
    try:
        results = service.users().messages().list(userId='me', q=query).execute()
        messages = results.get('messages', [])
        emails = []
        for msg in messages[:5]:  # Fetch first 5 emails
            email = service.users().messages().get(userId='me', id=msg['id']).execute()
            snippet = email.get('snippet', 'No content')
            emails.append(snippet)
        return emails
    except Exception as e:
        logger.error(f"Error fetching emails: {e}")
        st.error(f"An error occurred while fetching emails: {e}")
        return []

# Streamlit App
st.title("Gmail Dashboard")
st.write("Authenticate with Gmail and fetch your latest emails.")

if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if not st.session_state["authenticated"]:
    st.write("You need to authenticate to proceed.")
    service = authenticate_gmail()
    if service:
        st.session_state["authenticated"] = True
        st.session_state["service"] = service
else:
    st.write("You are authenticated!")
    service = st.session_state["service"]
    if st.button("Fetch Emails"):
        st.write("Fetching emails...")
        emails = fetch_emails(service)
        if emails:
            st.write("Fetched Emails:")
            for email in emails:
                st.write(email)
        else:
            st.write("No emails found.")
