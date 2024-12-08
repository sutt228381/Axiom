import os
import json
import streamlit as st
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import openai
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
CLIENT_SECRETS_FILE = "client_secrets.json"
TOKEN_FILE = "token.json"

# Function to create client secrets file
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
            }
        }
        with open(CLIENT_SECRETS_FILE, "w") as f:
            json.dump(client_secrets, f)
        logger.info("Client secrets file created successfully.")
    except Exception as e:
        logger.error(f"Error creating client_secrets.json: {e}")
        st.error(f"Error creating client_secrets.json: {e}")

# Function to authenticate user
def authenticate_user():
    create_client_secrets_file()
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
            return flow.credentials
    except Exception as e:
        logger.error(f"Error during authentication: {e}")
        st.error(f"Error during authentication: {e}")
        return None

# Function to fetch emails
def fetch_emails(service, query):
    try:
        results = service.users().messages().list(userId="me", q=query, maxResults=10).execute()
        messages = results.get("messages", [])
        email_data = []
        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            subject = next((header["value"] for header in msg["payload"]["headers"] if header["name"] == "Subject"), "No Subject")
            snippet = msg.get("snippet", "No snippet available")
            email_data.append({"Subject": subject, "Snippet": snippet})
        return email_data
    except HttpError as error:
        logger.error(f"Error fetching emails: {error}")
        st.error(f"Error fetching emails: {error}")
        return []

# Function to analyze emails with AI
def analyze_emails_with_ai(emails):
    st.subheader("AI Analysis of Emails")
    if not emails:
        st.write("No emails to analyze.")
        return

    try:
        email_texts = [f"Subject: {email['Subject']}\nSnippet: {email['Snippet']}" for email in emails]
        input_text = "\n\n".join(email_texts)

        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are an assistant helping to summarize emails."},
                {"role": "user", "content": input_text},
            ],
        )
        summary = response["choices"][0]["message"]["content"]
        st.write(summary)
    except openai.OpenAIError as e:
        logger.error(f"Error analyzing emails with OpenAI: {e}")
        st.error(f"Error analyzing emails with OpenAI: {e}")

# Function to display emails
def display_emails(emails):
    if not emails:
        st.write("No emails found.")
        return
    st.subheader("Emails Found:")
    for email in emails:
        st.write(f"**Subject:** {email['Subject']}")
        st.write(f"**Snippet:** {email['Snippet']}")
        st.markdown("---")

# Main function
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
        logger.error(f"Error creating Gmail service: {e}")
        st.error(f"Error creating Gmail service: {e}")
        return

    query = st.text_input("Enter a search query (e.g., 'bank statements'):")
    if query and st.button("Fetch Emails"):
        st.write("Fetching emails...")
        emails = fetch_emails(service, query)
        display_emails(emails)
        analyze_emails_with_ai(emails)

if __name__ == "__main__":
    main()
