import os
import json
import streamlit as st
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import pandas as pd
import matplotlib.pyplot as plt
import logging

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

def fetch_emails(service, query=""):
    try:
        results = service.users().messages().list(userId="me", q=query, maxResults=20).execute()
        messages = results.get("messages", [])
        email_data = []

        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            payload = msg.get("payload", {})
            headers = payload.get("headers", [])
            subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
            sender = next((h["value"] for h in headers if h["name"] == "From"), "Unknown Sender")
            date = next((h["value"] for h in headers if h["name"] == "Date"), "Unknown Date")
            snippet = msg.get("snippet", "No snippet available")

            email_data.append({"Subject": subject, "Sender": sender, "Date": date, "Snippet": snippet})

        return pd.DataFrame(email_data)
    except HttpError as error:
        logger.error(f"An error occurred: {error}")
        st.error(f"An error occurred: {error}")
        return pd.DataFrame()

def display_dashboard(email_data):
    st.header("Email Insights Dashboard")

    # Convert the "Date" column to datetime and set as index
    if 'Date' in email_data.columns:
        email_data['Date'] = pd.to_datetime(email_data['Date'], errors='coerce')
        email_data = email_data.dropna(subset=['Date'])  # Drop rows with invalid dates
        email_data.set_index('Date', inplace=True)

    # Visualization: Emails over time
    if not email_data.empty:
        emails_over_time = email_data.resample('D').size()
        st.subheader("Emails Over Time")
        st.bar_chart(emails_over_time)

        # Top senders visualization
        st.subheader("Top Email Senders")
        top_senders = email_data['Sender'].value_counts().head(10)
        st.bar_chart(top_senders)

        # Keywords in email subjects
        st.subheader("Frequent Keywords in Subjects")
        if 'Subject' in email_data.columns:
            from sklearn.feature_extraction.text import CountVectorizer
            vectorizer = CountVectorizer(stop_words='english', max_features=10)
            word_counts = vectorizer.fit_transform(email_data['Subject'].fillna(''))
            word_freq = pd.DataFrame(
                word_counts.toarray(), columns=vectorizer.get_feature_names_out()
            ).sum().sort_values(ascending=False)
            st.bar_chart(word_freq)

    else:
        st.warning("No valid data available for visualization.")

def main():
    st.title("Gmail AI Dashboard")
    email = st.text_input("Enter your email address:")
    query = st.text_input("What would you like to search for in your inbox?")

    if st.button("Authenticate and Fetch Emails"):
        creds = authenticate_user()
        if creds:
            service = build("gmail", "v1", credentials=creds)
            st.write(f"Fetching emails for query: {query}")
            email_data = fetch_emails(service, query=query)
            if not email_data.empty:
                display_dashboard(email_data)
            else:
                st.warning("No emails matched your query.")

if __name__ == "__main__":
    main()
