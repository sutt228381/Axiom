import os
import json
import logging
import streamlit as st
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import matplotlib.pyplot as plt
import pandas as pd

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Paths and constants
CLIENT_SECRETS_FILE = "client_secrets.json"
TOKEN_FILE = "token.json"

def create_client_secrets_file():
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

def authenticate_user():
    create_client_secrets_file()
    try:
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
    except Exception as e:
        logger.error(f"Error during Gmail authentication: {e}")
        st.error(f"Error during Gmail authentication: {e}")
        return None

def fetch_emails(service, query):
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
    except HttpError as error:
        logger.error(f"An error occurred: {error}")
        st.error(f"An error occurred: {error}")
        return pd.DataFrame()

def display_dashboard(email_data):
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

def analyze_emails(email_data):
    st.subheader("Categorized Emails")
    categories = {
        "Actions Needed": email_data[email_data["Snippet"].str.contains("action", na=False, case=False)],
        "Questions": email_data[email_data["Snippet"].str.contains("question", na=False, case=False)],
        "Upcoming Events": email_data[email_data["Snippet"].str.contains("event|schedule", na=False, case=False)]
    }
    for category, data in categories.items():
        st.write(f"### {category}")
        st.dataframe(data)

def main():
    st.title("Gmail BI Dashboard")
    st.write("Enter your email and search query:")
    email = st.text_input("Email Address")
    query = st.text_input("Search Query (e.g., 'bank statements', 'meetings')")

    if email and st.button("Authenticate and Fetch Emails"):
        creds = authenticate_user()
        if creds:
            service = build("gmail", "v1", credentials=creds)
            st.write("Authentication successful. Fetching emails...")
            email_data = fetch_emails(service, query)
            if not email_data.empty:
                display_dashboard(email_data)
                analyze_emails(email_data)
            else:
                st.write("No relevant emails found.")

if __name__ == "__main__":
    main()
