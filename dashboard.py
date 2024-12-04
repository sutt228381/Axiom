import os
import json
import streamlit as st
import openai
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
CLIENT_SECRETS_FILE = "client_secrets.json"
TOKEN_FILE = "token.json"
openai.api_key = st.secrets["openai_api_key"]

def create_client_secrets_file():
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

def load_token():
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r") as token_file:
            return json.load(token_file)
    return None

def authenticate_user():
    create_client_secrets_file()
    token_data = load_token()

    if token_data:
        from google.oauth2.credentials import Credentials
        creds = Credentials.from_authorized_user_info(token_data)
        return creds

    try:
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
            redirect_uri=st.secrets["web"]["redirect_uris"][0],
        )
        auth_url, _ = flow.authorization_url(prompt="consent")
        st.write(f"[Click here to authenticate]({auth_url})")

        code = st.experimental_get_query_params().get("code")
        if code:
            flow.fetch_token(code=code[0])
            creds = flow.credentials
            with open(TOKEN_FILE, "w") as token_file:
                token_file.write(creds.to_json())
            return creds
    except Exception as e:
        st.error(f"Error during Gmail authentication: {e}")
        return None

def fetch_emails(service, query):
    try:
        results = service.users().messages().list(userId="me", q=query, maxResults=20).execute()
        messages = results.get("messages", [])
        emails = []
        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            headers = {h["name"]: h["value"] for h in msg["payload"]["headers"]}
            date = headers.get("Date", "No Date")
            subject = headers.get("Subject", "No Subject")
            snippet = msg.get("snippet", "No snippet available")
            emails.append({"Date": date, "Subject": subject, "Snippet": snippet})
        return emails
    except HttpError as error:
        st.error(f"An error occurred: {error}")
        return []

def analyze_emails_with_ai(emails, user_query):
    combined_text = " ".join([email["Snippet"] for email in emails])
    prompt = f"""
    You are an intelligent assistant. Analyze the following email data and respond to the user query:
    User Query: {user_query}
    Email Data: {combined_text}
    Provide an organized summary, including any trends, key insights, and structured data.
    """
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message["content"]
    except Exception as e:
        st.error(f"Error analyzing emails: {e}")
        return None

def display_dashboard(analysis, emails):
    st.subheader("AI Analysis")
    st.write(analysis)

    st.subheader("Visualizations")
    try:
        email_df = pd.DataFrame(emails)
        email_df["Date"] = pd.to_datetime(email_df["Date"], errors="coerce")
        email_df = email_df.dropna(subset=["Date"])

        monthly_counts = email_df.resample("M", on="Date").size()
        st.bar_chart(monthly_counts)
    except Exception as e:
        st.error(f"Error creating visualizations: {e}")

def main():
    st.title("AI-Powered Gmail Dashboard")
    st.write("Authenticate and analyze your Gmail inbox.")
    creds = authenticate_user()
    if not creds:
        return

    try:
        service = build("gmail", "v1", credentials=creds)
        st.success("Authentication successful!")
    except Exception as e:
        st.error(f"Error creating Gmail service: {e}")
        return

    user_query = st.text_input("What are you looking for in your emails?")
    if user_query and st.button("Fetch and Analyze Emails"):
        emails = fetch_emails(service, user_query)
        analysis = analyze_emails_with_ai(emails, user_query)
        display_dashboard(analysis, emails)

if __name__ == "__main__":
    main()
