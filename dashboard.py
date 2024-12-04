import os
import json
import streamlit as st
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import openai
import pandas as pd
import matplotlib.pyplot as plt

# Set up OpenAI API key
openai.api_key = st.secrets["openai_api_key"]

# Paths and constants
CLIENT_SECRETS_FILE = "client_secrets.json"
TOKEN_FILE = "token.json"

def create_client_secrets_file():
    """Create a client_secrets.json file from Streamlit secrets."""
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

def authenticate_user():
    """Authenticate the user with Gmail API."""
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
        return creds
    return None

def fetch_emails(service, query=""):
    """Fetch emails from the Gmail API based on the query."""
    results = service.users().messages().list(userId="me", q=query, maxResults=20).execute()
    messages = results.get("messages", [])
    email_data = []
    for message in messages:
        msg = service.users().messages().get(userId="me", id=message["id"]).execute()
        email_data.append({
            "Subject": next((header["value"] for header in msg["payload"]["headers"] if header["name"] == "Subject"), "No Subject"),
            "Snippet": msg.get("snippet", "No snippet available")
        })
    return email_data

def analyze_emails_with_ai(email_data):
    """Analyze and organize email data using AI."""
    organized_data = {"Actions Needed": [], "Upcoming Events": [], "General Info": []}
    for email in email_data:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are an assistant organizing email content."},
                {"role": "user", "content": f"Organize this email: {email['Snippet']}"}
            ]
        )
        summary = response.choices[0].message["content"]
        if "action" in summary.lower():
            organized_data["Actions Needed"].append(email)
        elif "event" in summary.lower():
            organized_data["Upcoming Events"].append(email)
        else:
            organized_data["General Info"].append(email)
    return organized_data

def display_dashboard(organized_data):
    """Display organized email data on the dashboard."""
    st.header("Email Dashboard")

    for category, emails in organized_data.items():
        st.subheader(category)
        for email in emails:
            st.write(f"**Subject:** {email['Subject']}")
            st.write(f"**Snippet:** {email['Snippet']}")
            st.markdown("---")

def main():
    st.title("AI-Powered Gmail Dashboard")
    st.write("Authenticate and analyze your Gmail inbox.")

    creds = authenticate_user()
    if creds:
        service = build("gmail", "v1", credentials=creds)

        query = st.text_input("Enter a query (e.g., 'bank statements'):")
        if st.button("Fetch and Analyze Emails"):
            email_data = fetch_emails(service, query)
            organized_data = analyze_emails_with_ai(email_data)
            display_dashboard(organized_data)

if __name__ == "__main__":
    main()
