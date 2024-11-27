import os
import json
import openai
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
    """Creates a client_secrets.json file dynamically from Streamlit secrets."""
    try:
        client_secrets = {
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
        with open(CLIENT_SECRETS_FILE, "w") as f:
            json.dump(client_secrets, f)
        logger.info("Client secrets file created successfully.")
    except Exception as e:
        logger.error(f"Error creating client_secrets.json: {e}")
        st.error(f"Error creating client_secrets.json: {e}")

def authenticate_user():
    """Handles Gmail API authentication."""
    create_client_secrets_file()
    try:
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
            redirect_uri=st.secrets["web"]["redirect_uris"][0]
        )
        auth_url, _ = flow.authorization_url(prompt="consent")
        st.write(f"[Click here to authenticate your Gmail account]({auth_url})")
        code = st.text_input("Enter the authorization code here:")
        if code:
            flow.fetch_token(code=code)
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
    """Fetches emails from Gmail based on the user's query."""
    try:
        results = service.users().messages().list(userId="me", q=query, maxResults=50).execute()
        messages = results.get("messages", [])
        email_data = []
        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            snippet = msg.get("snippet", "No snippet available")
            headers = msg.get("payload", {}).get("headers", [])
            date = next((h["value"] for h in headers if h["name"] == "Date"), "Unknown Date")
            subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
            email_data.append({"Date": pd.to_datetime(date, errors="coerce"), "Subject": subject, "Snippet": snippet})
        return pd.DataFrame(email_data)
    except HttpError as error:
        logger.error(f"An error occurred while fetching emails: {error}")
        st.error(f"An error occurred while fetching emails: {error}")
        return pd.DataFrame()

def analyze_and_visualize_emails(email_data):
    """Analyzes and visualizes email data."""
    try:
        st.write("### Email Dashboard")

        # Emails over time
        st.write("#### Emails Over Time")
        email_data['Date'] = pd.to_datetime(email_data['Date'], errors='coerce')
        email_data = email_data.dropna(subset=['Date'])
        emails_over_time = email_data['Date'].dt.date.value_counts().sort_index()
        plt.figure(figsize=(10, 5))
        plt.plot(emails_over_time.index, emails_over_time.values, marker='o')
        plt.title("Emails Over Time")
        plt.xlabel("Date")
        plt.ylabel("Number of Emails")
        plt.xticks(rotation=45)
        st.pyplot(plt)

        # Display email subjects and snippets
        st.write("#### Emails:")
        for _, row in email_data.iterrows():
            st.write(f"**Subject**: {row['Subject']}")
            st.write(f"**Snippet**: {row['Snippet']}")
            st.write("---")

        # Use OpenAI to summarize emails
        st.write("#### AI Summary of Emails")
        summaries = []
        for _, row in email_data.iterrows():
            prompt = f"Summarize this email content: {row['Snippet']}"
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[{"role": "system", "content": "You are an assistant that summarizes emails."},
                          {"role": "user", "content": prompt}]
            )
            summaries.append(response.choices[0].message['content'])
        for summary in summaries:
            st.write(f"- {summary}")
    except Exception as e:
        logger.error(f"Error analyzing emails: {e}")
        st.error(f"Error analyzing emails: {e}")

def main():
    """Main Streamlit app."""
    st.title("Dynamic Gmail Dashboard with AI Insights")

    # OpenAI API key setup
    try:
        openai.api_key = st.secrets["openai_api_key"]
    except KeyError:
        st.error("OpenAI API Key is missing. Please add it to Streamlit secrets.")
        return

    email_address = st.text_input("Enter your Gmail address to authenticate:")
    if st.button("Authenticate"):
        creds = authenticate_user()
        if creds:
            service = build("gmail", "v1", credentials=creds)
            st.success("Authentication successful! You can now search your emails.")

            query = st.text_input("Enter a search query (e.g., 'TDBank statements'):")
            if st.button("Fetch Emails"):
                email_data = fetch_emails(service, query)
                if not email_data.empty:
                    analyze_and_visualize_emails(email_data)
                else:
                    st.warning("No emails found for the given query.")

if __name__ == "__main__":
    main()
