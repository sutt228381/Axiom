import os
import json
import streamlit as st
import openai
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Paths and constants
CLIENT_SECRETS_FILE = "client_secrets.json"
TOKEN_FILE = "token.json"

# Set OpenAI API key
openai.api_key = st.secrets["openai_api_key"]

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

def fetch_emails(service, user_query):
    try:
        results = service.users().messages().list(userId="me", q=user_query, maxResults=50).execute()
        messages = results.get("messages", [])
        email_data = []
        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            snippet = msg.get("snippet", "No snippet available")
            email_data.append({
                "Date": datetime.fromtimestamp(int(msg["internalDate"]) / 1000),
                "Snippet": snippet
            })
        return pd.DataFrame(email_data)
    except HttpError as error:
        logger.error(f"An error occurred: {error}")
        st.error(f"An error occurred: {error}")
        return pd.DataFrame()

def analyze_emails_with_openai(email_data):
    try:
        summaries = []
        for _, row in email_data.iterrows():
            prompt = f"Summarize this email: {row['Snippet']}"
            response = openai.Completion.create(
                engine="text-davinci-003",
                prompt=prompt,
                max_tokens=50
            )
            summary = response.choices[0].text.strip()
            summaries.append(summary)
        email_data["Summary"] = summaries
        return email_data
    except Exception as e:
        logger.error(f"Error analyzing emails: {e}")
        st.error(f"Error analyzing emails: {e}")
        return email_data

def display_dashboard(email_data):
    st.header("Email Insights Dashboard")
    if email_data.empty:
        st.write("No data available to display.")
        return

    # Display a bar chart of emails over time
    email_data["Date"] = pd.to_datetime(email_data["Date"])
    email_data.set_index("Date", inplace=True)
    emails_over_time = email_data.resample("D").size()

    st.subheader("Emails Over Time")
    st.line_chart(emails_over_time)

    st.subheader("Email Summaries")
    for index, row in email_data.iterrows():
        st.write(f"**Date:** {index}")
        st.write(f"**Summary:** {row['Summary']}")

def main():
    st.title("Gmail AI-Powered Dashboard")

    user_email = st.text_input("Enter your email address:", "")
    user_query = st.text_input("What would you like to analyze? (e.g., 'TD Bank')", "")

    if st.button("Authenticate and Fetch Emails"):
        creds = authenticate_user()
        if creds:
            service = build("gmail", "v1", credentials=creds)
            st.write("Authentication successful. Fetching emails...")
            email_data = fetch_emails(service, user_query)
            if not email_data.empty:
                email_data = analyze_emails_with_openai(email_data)
                display_dashboard(email_data)

if __name__ == "__main__":
    main()
