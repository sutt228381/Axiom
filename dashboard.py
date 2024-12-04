import os
import json
import streamlit as st
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
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
            }
        }
        with open(CLIENT_SECRETS_FILE, "w") as f:
            json.dump(client_secrets, f)
        logger.info("Client secrets file created successfully.")
    except Exception as e:
        logger.error(f"Error creating client_secrets.json: {e}")
        st.error(f"Error creating client_secrets.json: {e}")

def load_token():
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r") as token:
            logger.info("Token loaded from file.")
            return json.load(token)
    return None

def authenticate_user():
    create_client_secrets_file()
    creds = load_token()
    if creds:
        return creds

    try:
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
            redirect_uri=st.secrets["web"]["redirect_uris"][0],
        )
        auth_url, _ = flow.authorization_url(prompt="consent")
        st.write(f"[Click here to authenticate]({auth_url})")

        # Wait for user to authenticate
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
        results = service.users().messages().list(userId="me", q=query, maxResults=10).execute()
        messages = results.get("messages", [])
        email_data = []
        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            subject = next(
                (header["value"] for header in msg["payload"]["headers"] if header["name"] == "Subject"), 
                "No Subject"
            )
            snippet = msg.get("snippet", "No snippet available")
            email_data.append({"Subject": subject, "Snippet": snippet})
        return email_data
    except HttpError as error:
        logger.error(f"An error occurred: {error}")
        st.error(f"An error occurred: {error}")
        return []

def display_emails(emails):
    if not emails:
        st.write("No emails found.")
        return

    st.subheader("Emails Found:")
    for email in emails:
        st.write(f"**Subject:** {email['Subject']}")
        st.write(f"**Snippet:** {email['Snippet']}")
        st.markdown("---")

def main():
    st.title("AI-Powered Gmail Dashboard")
    st.write("Authenticate and analyze your Gmail inbox.")

    # Step 1: Authenticate user
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

    # Step 2: Query input
    query = st.text_input("Enter a search query (e.g., 'bank statements'):")
    if query and st.button("Fetch Emails"):
        st.write("Fetching emails...")
        emails = fetch_emails(service, query)
        display_emails(emails)

if __name__ == "__main__":
    main()
