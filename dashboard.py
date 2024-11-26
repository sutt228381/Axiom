import os
import json
import openai
import pandas as pd
import streamlit as st
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import matplotlib.pyplot as plt
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set OpenAI API key
openai.api_key = st.secrets["openai_api_key"]

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
        results = service.users().messages().list(userId="me", q=query, maxResults=50).execute()
        messages = results.get("messages", [])
        email_data = []
        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            snippet = msg.get("snippet", "No snippet available")
            internal_date = int(msg.get("internalDate", 0)) / 1000
            date = datetime.utcfromtimestamp(internal_date).strftime('%Y-%m-%d')
            email_data.append({"Date": date, "Snippet": snippet})
        return pd.DataFrame(email_data)
    except HttpError as error:
        logger.error(f"An error occurred while fetching emails: {error}")
        st.error(f"An error occurred while fetching emails: {error}")
        return pd.DataFrame()

def analyze_emails_with_openai(email_data):
    try:
        analysis_text = "Summarize the following email snippets into key insights, including actions, questions, and timelines:\n"
        for snippet in email_data["Snippet"]:
            analysis_text += f"- {snippet}\n"

        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "system", "content": "You are an assistant that organizes email content into meaningful insights."},
                      {"role": "user", "content": analysis_text}]
        )
        summary = response["choices"][0]["message"]["content"]
        return summary
    except Exception as e:
        logger.error(f"Error analyzing emails with OpenAI: {e}")
        st.error(f"Error analyzing emails: {e}")
        return None

def display_dashboard(email_data, analysis_summary):
    st.subheader("Email Insights Dashboard")

    # Emails over time
    st.subheader("Emails Over Time")
    email_data["Date"] = pd.to_datetime(email_data["Date"])
    emails_over_time = email_data["Date"].value_counts().sort_index()
    plt.figure(figsize=(10, 5))
    plt.bar(emails_over_time.index, emails_over_time.values)
    plt.title("Emails Over Time")
    plt.xlabel("Date")
    plt.ylabel("Number of Emails")
    st.pyplot(plt)

    # OpenAI Insights
    if analysis_summary:
        st.subheader("AI-Generated Insights")
        st.write(analysis_summary)

def main():
    st.title("Gmail Insights Dashboard")
    st.write("Enter your Gmail address and search query to fetch insights.")

    email_address = st.text_input("Enter your Gmail address:", "")
    query = st.text_input("Enter a search query (e.g., 'TD Bank statements'):", "")

    if st.button("Fetch and Analyze Emails"):
        creds = authenticate_user()
        if creds:
            service = build("gmail", "v1", credentials=creds)
            st.write("Fetching emails...")
            email_data = fetch_emails(service, query)
            if not email_data.empty:
                st.write(f"Fetched {len(email_data)} emails.")
                analysis_summary = analyze_emails_with_openai(email_data)
                display_dashboard(email_data, analysis_summary)
            else:
                st.write("No emails found for the given query.")

if __name__ == "__main__":
    main()
