import os
import json
import streamlit as st
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from openai import OpenAI
import matplotlib.pyplot as plt
import logging
from collections import Counter

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Paths and constants
CLIENT_SECRETS_FILE = "client_secrets.json"
TOKEN_FILE = "token.json"

# OpenAI API key (ensure this is set in Streamlit secrets)
OPENAI_API_KEY = st.secrets["openai"]["api_key"]

# Create client secrets file
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

# Authenticate Gmail API
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

# Fetch emails
def fetch_emails(service):
    try:
        results = service.users().messages().list(userId="me", labelIds=["INBOX"], maxResults=20).execute()
        messages = results.get("messages", [])
        email_snippets = []
        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            snippet = msg.get("snippet", "No snippet available")
            email_snippets.append(snippet)
        return email_snippets
    except HttpError as error:
        logger.error(f"An error occurred: {error}")
        st.error(f"An error occurred: {error}")
        return []

# Analyze emails with OpenAI
def analyze_emails(email_snippets):
    try:
        openai.api_key = OPENAI_API_KEY
        summary = []
        categories = []
        for snippet in email_snippets:
            response = openai.Completion.create(
                model="text-davinci-003",
                prompt=f"Categorize this email: '{snippet}' and summarize it in one sentence.",
                max_tokens=50
            )
            summary_text = response["choices"][0]["text"].strip()
            category, summary_snippet = summary_text.split(":")
            categories.append(category.strip())
            summary.append({"category": category.strip(), "summary": summary_snippet.strip()})
        return summary, categories
    except Exception as e:
        logger.error(f"Error analyzing emails: {e}")
        st.error(f"Error analyzing emails: {e}")
        return [], []

# Visualize email categories
def visualize_categories(categories):
    category_counts = Counter(categories)
    fig, ax = plt.subplots()
    ax.bar(category_counts.keys(), category_counts.values())
    ax.set_title("Email Categories")
    ax.set_ylabel("Number of Emails")
    ax.set_xlabel("Categories")
    plt.xticks(rotation=45)
    st.pyplot(fig)

# Display dashboard
def main():
    st.title("Gmail Dashboard with AI-Powered Visualizations")
    st.write("Enter your email and topic to get started.")

    creds = authenticate_user()
    if creds:
        service = build("gmail", "v1", credentials=creds)
        st.write("Authentication successful. Fetching emails...")
        email_snippets = fetch_emails(service)
        if email_snippets:
            st.write("Analyzing emails...")
            summaries, categories = analyze_emails(email_snippets)
            st.write("### Summaries of Emails:")
            for summary in summaries:
                st.write(f"- **Category**: {summary['category']}")
                st.write(f"  - {summary['summary']}")
            st.write("### Visualization of Email Categories")
            visualize_categories(categories)

if __name__ == "__main__":
    main()
