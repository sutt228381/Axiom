import os
import logging
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import streamlit as st

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Set environment variables
os.environ["GOOGLE_CLOUD_PROJECT"] = "concise-rex-442402-b5"
os.environ["NO_GCE_CHECK"] = "true"  # Avoid Compute Engine Metadata warnings

# Gmail API Scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


# Authenticate the user using manual URL-based flow
def authenticate_gmail():
    logger.info("Starting Gmail authentication...")

    flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)

    try:
        # Generate the authorization URL
        auth_url, _ = flow.authorization_url(prompt='consent')
        st.info("Please click the link below to authorize access:")
        st.write(f"[Authorize Gmail Access]({auth_url})")

        # Input field for the authorization code
        auth_code = st.text_input("Enter the authorization code after authorizing:")

        # Handle the input and exchange the code for credentials
        if auth_code:
            creds = flow.fetch_token(code=auth_code)
            logger.info("OAuth flow completed successfully.")
            return flow.credentials
    except Exception as e:
        logger.error("Error during OAuth flow: %s", e)
        st.error("An error occurred during authentication.")
        raise e

    return None


# Fetch emails
def fetch_emails(service, query="label:inbox"):
    logger.info("Fetching emails with query: %s", query)
    try:
        results = service.users().messages().list(userId='me', q=query).execute()
        messages = results.get('messages', [])
        emails = []

        if not messages:
            st.write("No emails found.")
            return emails

        for msg in messages[:5]:
            email = service.users().messages().get(userId='me', id=msg['id']).execute()
            snippet = email.get('snippet', 'No content')
            emails.append({"id": msg['id'], "snippet": snippet})

        return emails
    except Exception as e:
        logger.error("Error fetching emails: %s", e)
        st.error("Failed to fetch emails.")
        return []


# Streamlit UI
st.title("Gmail Dashboard")
st.write("A dashboard to view and analyze your Gmail data.")

# Authenticate and fetch emails
if st.button("Authenticate and Fetch Emails"):
    try:
        creds = authenticate_gmail()
        if creds:
            service = build('gmail', 'v1', credentials=creds)
            emails = fetch_emails(service)
            if emails:
                st.write("Fetched Emails:")
                for email in emails:
                    st.write(f"**ID**: {email['id']}")
                    st.write(f"**Snippet**: {email['snippet']}")
                    st.write("---")
    except Exception as e:
        st.error(f"An error occurred: {e}")

st.write("Powered by Gmail API and Streamlit.")
