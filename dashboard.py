import os
import logging
import streamlit as st
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import pickle
import pandas as pd

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Gmail API Scope
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Initialize credentials storage
TOKEN_FILE = "token.pickle"

# Function: Authenticate Gmail
def authenticate_gmail():
    creds = None

    # Load credentials if available
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "rb") as token:
            creds = pickle.load(token)
            logger.info("Loaded existing credentials.")

    # Refresh or request new credentials if necessary
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logger.info("Refreshing credentials...")
            creds.refresh(Request())
        else:
            logger.info("Starting OAuth flow...")
            flow = Flow.from_client_secrets_file(
                "client_secrets.json", scopes=SCOPES
            )
            flow.redirect_uri = st.secrets["web"]["redirect_uris"][0]
            auth_url, _ = flow.authorization_url(prompt="consent")
            st.write(f"[Authenticate Gmail]({auth_url})")
            st.stop()  # Wait for user authentication

    return creds

# Function: Fetch Emails
def fetch_emails(service, query="label:inbox"):
    logger.info("Fetching emails...")
    results = service.users().messages().list(userId="me", q=query).execute()
    messages = results.get("messages", [])
    email_data = []

    for msg in messages[:10]:  # Fetch first 10 emails
        email = service.users().messages().get(userId="me", id=msg["id"]).execute()
        headers = email.get("payload", {}).get("headers", [])
        snippet = email.get("snippet", "")
        subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
        sender = next((h["value"] for h in headers if h["name"] == "From"), "Unknown Sender")
        email_data.append({"Subject": subject, "Sender": sender, "Snippet": snippet})

    return email_data

# Streamlit UI
st.title("📧 Gmail Dashboard")
st.write("Authenticate and view your Gmail data in one place.")

# Authenticate and Fetch
if st.button("Authenticate and Fetch Emails"):
    try:
        creds = authenticate_gmail()
        service = build("gmail", "v1", credentials=creds)
        emails = fetch_emails(service)
        
        if emails:
            df = pd.DataFrame(emails)
            st.write("### Fetched Emails")
            st.dataframe(df)
        else:
            st.write("No emails found.")

    except Exception as e:
        st.error(f"An error occurred: {e}")
        logger.error("Error: %s", e)
