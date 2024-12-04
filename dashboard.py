import os
import json
import streamlit as st
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

# File paths
CLIENT_SECRETS_FILE = "client_secrets.json"
TOKEN_FILE = "token.json"

def create_client_secrets_file():
    """Create client_secrets.json dynamically."""
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
    except Exception as e:
        st.error(f"Error creating client_secrets.json: {e}")

def authenticate_user():
    """Authenticate the user and save the token."""
    try:
        if os.path.exists(TOKEN_FILE):
            with open(TOKEN_FILE, "r") as token:
                creds = Credentials.from_authorized_user_info(json.load(token))
                if creds and creds.valid:
                    return creds
                elif creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                    return creds
        else:
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
    except Exception as e:
        st.error(f"Error during Gmail authentication: {e}")
        return None

def fetch_emails(service):
    """Fetch the user's emails."""
    try:
        results = service.users().messages().list(userId="me", labelIds=["INBOX"], maxResults=10).execute()
        messages = results.get("messages", [])
        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            st.write(msg.get("snippet", "No content available"))
    except Exception as e:
        st.error(f"Error fetching emails: {e}")

def main():
    st.title("Gmail Dashboard")
    creds = authenticate_user()
    if creds:
        service = build("gmail", "v1", credentials=creds)
        st.write("Authenticated successfully!")
        if st.button("Fetch Emails"):
            fetch_emails(service)

if __name__ == "__main__":
    main()
