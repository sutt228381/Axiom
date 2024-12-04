import os
import json
import logging
import streamlit as st
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
CLIENT_SECRETS_FILE = "client_secrets.json"

def create_client_secrets_file():
    """Create the client_secrets.json file dynamically."""
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
    """Authenticate the user and manage the token using session state."""
    if "token" in st.session_state:
        # Use existing token in session state
        creds = Credentials.from_authorized_user_info(st.session_state["token"])
        if creds and creds.valid:
            return creds
        elif creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            st.session_state["token"] = json.loads(creds.to_json())
            return creds
    else:
        # Start OAuth flow
        try:
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
                st.session_state["token"] = json.loads(creds.to_json())
                return creds
        except Exception as e:
            logger.error(f"Error during Gmail authentication: {e}")
            st.error(f"Error during Gmail authentication: {e}")
            return None

def fetch_emails(service, query):
    """Fetch and display emails based on a query."""
    try:
        results = service.users().messages().list(userId="me", q=query, maxResults=10).execute()
        messages = results.get("messages", [])
        email_snippets = []
        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            snippet = msg.get("snippet", "No snippet available")
            email_snippets.append(snippet)
        if email_snippets:
            st.write(f"Fetched Emails for query: '{query}'")
            for i, snippet in enumerate(email_snippets, 1):
                st.write(f"{i}. {snippet}")
        else:
            st.write(f"No emails found for query: '{query}'.")
    except HttpError as error:
        logger.error(f"An error occurred: {error}")
        st.error(f"An error occurred: {error}")

def main():
    """Main function for the Streamlit app."""
    st.title("Gmail Dashboard")

    # Input for email prompt
    email_prompt = st.text_input("Enter the email address you'd like to use:")
    if email_prompt:
        st.write(f"Using email: {email_prompt}")

        # Authenticate the user
        creds = authenticate_user()
        if creds:
            service = build("gmail", "v1", credentials=creds)
            st.write("Authenticated successfully!")

            # Input for search query
            search_query = st.text_input("What would you like to search for in your inbox?")
            if search_query and st.button("Fetch Emails"):
                fetch_emails(service, search_query)

        if st.button("Log Out"):
            if "token" in st.session_state:
                del st.session_state["token"]
            st.write("Logged out successfully.")

if __name__ == "__main__":
    main()
