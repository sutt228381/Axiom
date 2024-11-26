import os
import json
import logging
import streamlit as st
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import pandas as pd

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# File paths and constants
CLIENT_SECRETS_FILE = "client_secrets.json"
TOKEN_FILE = "token.json"

def create_client_secrets_file():
    """Create the client_secrets.json file dynamically."""
    try:
        client_secrets = {
            "web": {
                "client_id": st.secrets["web"]["client_id"],
                "project_id": st.secrets["web"]["project_id"],
                "auth_uri": st.secrets["web"]["auth_uri"],
                "token_uri": st.secrets["web"]["token_uri"],
                "auth_provider_x509_cert_url": st.secrets["web"]["auth_provider_x509_cert_url"],
                "client_secret": st.secrets["web"]["client_secret"],
                "redirect_uris": st.secrets["web"]["redirect_uris"],
                "javascript_origins": st.secrets["web"]["javascript_origins"],
            }
        }
        with open(CLIENT_SECRETS_FILE, "w") as f:
            json.dump(client_secrets, f)
        logger.info("Client secrets file created successfully.")
    except Exception as e:
        logger.error(f"Error creating client_secrets.json: {e}")
        st.error(f"Error creating client_secrets.json: {e}")

def load_credentials():
    """Load credentials from token file or initiate the OAuth flow."""
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, scopes=["https://www.googleapis.com/auth/gmail.readonly"])
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            create_client_secrets_file()
            flow = Flow.from_client_secrets_file(
                CLIENT_SECRETS_FILE,
                scopes=["https://www.googleapis.com/auth/gmail.readonly"],
                redirect_uri=st.secrets["web"]["redirect_uris"][0]
            )
            auth_url, _ = flow.authorization_url(prompt="consent")
            st.write(f"[Click here to authenticate]({auth_url})")
            code = st.experimental_get_query_params().get("code")
            if code:
                flow.fetch_token(code=code[0])
                creds = flow.credentials
                with open(TOKEN_FILE, "w") as token:
                    token.write(creds.to_json())
                logger.info("Token saved successfully.")
    return creds

def fetch_emails(service, query):
    """Fetch emails from the Gmail API."""
    try:
        results = service.users().messages().list(userId="me", q=query, maxResults=50).execute()
        messages = results.get("messages", [])
        email_data = []
        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            snippet = msg.get("snippet", "No snippet available")
            headers = {h['name']: h['value'] for h in msg['payload']['headers']}
            email_data.append({
                "From": headers.get("From", "Unknown"),
                "Subject": headers.get("Subject", "No Subject"),
                "Snippet": snippet,
                "Date": headers.get("Date", "Unknown")
            })
        return pd.DataFrame(email_data)
    except Exception as e:
        logger.error(f"An error occurred while fetching emails: {e}")
        st.error(f"An error occurred while fetching emails: {e}")
        return pd.DataFrame()

def display_dashboard(email_data):
    """Display a BI-style dashboard for the emails."""
    st.subheader("Email Dashboard")
    if email_data.empty:
        st.write("No emails found.")
        return

    # Summary Statistics
    st.write(f"Total Emails: {len(email_data)}")
    st.write(f"Unique Senders: {email_data['From'].nunique()}")
    
    # Bar Chart: Emails per Sender
    sender_counts = email_data['From'].value_counts().head(10)
    st.bar_chart(sender_counts)

    # Line Chart: Emails Over Time
    email_data['Date'] = pd.to_datetime(email_data['Date'], errors='coerce')
    emails_over_time = email_data.set_index('Date').resample('D').size()
    st.line_chart(emails_over_time)

    # Table of Emails
    st.dataframe(email_data)

def main():
    """Main entry point for the Streamlit app."""
    st.title("Gmail BI Dashboard")
    st.write("Enter your email and search query to fetch and analyze your inbox.")

    # Input fields
    email = st.text_input("Email Address")
    query = st.text_input("Search Query (e.g., 'bank statements', 'meetings')")

    if st.button("Authenticate and Fetch Emails"):
        creds = load_credentials()
        if creds:
            service = build("gmail", "v1", credentials=creds)
            st.write("Authentication successful. Fetching emails...")
            email_data = fetch_emails(service, query)
            if not email_data.empty:
                display_dashboard(email_data)
            else:
                st.write("No relevant emails found.")

if __name__ == "__main__":
    main()
