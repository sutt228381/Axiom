import os
import json
import streamlit as st
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import openai
import logging
import pandas as pd
import matplotlib.pyplot as plt

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
CLIENT_SECRETS_FILE = "client_secrets.json"
TOKEN_FILE = "token.json"

def create_client_secrets_file():
    """
    Dynamically creates the client_secrets.json file using Streamlit secrets.
    """
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
            }
        }
        with open(CLIENT_SECRETS_FILE, "w") as f:
            json.dump(client_secrets, f)
        logger.info("Client secrets file created successfully.")
    except Exception as e:
        logger.error(f"Error creating client_secrets.json: {e}")
        st.error(f"Error creating client_secrets.json: {e}")

def authenticate_user():
    """
    Handles Gmail API authentication via OAuth.
    """
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
    """
    Fetches emails from the Gmail inbox based on the given query.
    """
    try:
        results = service.users().messages().list(userId="me", q=query, maxResults=10).execute()
        messages = results.get("messages", [])
        email_data = []
        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            snippet = msg.get("snippet", "No snippet available")
            email_data.append({"Snippet": snippet, "Date": pd.to_datetime(msg["internalDate"], unit="ms")})
        return pd.DataFrame(email_data)
    except HttpError as error:
        logger.error(f"An error occurred: {error}")
        st.error(f"An error occurred: {error}")
        return pd.DataFrame()

def analyze_emails(email_data):
    """
    Uses OpenAI to analyze email snippets and generate insights.
    """
    try:
        email_text = "\n".join(email_data["Snippet"].tolist())
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are an assistant helping to analyze email content."},
                {"role": "user", "content": f"Analyze these emails and generate a report:\n{email_text}"}
            ]
        )
        return response["choices"][0]["message"]["content"]
    except Exception as e:
        logger.error(f"Error analyzing emails: {e}")
        st.error(f"Error analyzing emails: {e}")
        return "No analysis available."

def display_dashboard(email_data):
    """
    Displays a BI dashboard based on email data.
    """
    if email_data.empty:
        st.write("No emails to display.")
        return

    # Emails over time
    email_data.set_index("Date", inplace=True)
    emails_over_time = email_data.resample("D").size()
    plt.figure(figsize=(10, 5))
    plt.bar(emails_over_time.index, emails_over_time.values)
    plt.title("Emails Over Time")
    plt.xlabel("Date")
    plt.ylabel("Number of Emails")
    st.pyplot(plt)

    # Show email snippets
    st.write("### Email Snippets")
    for _, row in email_data.iterrows():
        st.write(f"- {row['Snippet']}")

def main():
    """
    Main function to run the Streamlit app.
    """
    st.title("Dynamic Email Dashboard")
    openai.api_key = st.secrets["openai_api_key"]

    email = st.text_input("Enter your email address")
    query = st.text_input("What would you like to search for in your inbox?")
    if email and query:
        creds = authenticate_user()
        if creds:
            service = build("gmail", "v1", credentials=creds)
            email_data = fetch_emails(service, query)
            if not email_data.empty:
                analysis = analyze_emails(email_data)
                st.write("### Email Analysis")
                st.write(analysis)
                display_dashboard(email_data)

if __name__ == "__main__":
    main()
