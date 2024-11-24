import os
import json
import pickle
import logging
import streamlit as st
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# App title
st.title("Gmail Dashboard")

# Dynamically create client secrets file
def create_client_secrets_file():
    client_secrets = {
        "web": {
            "client_id": st.secrets["google"]["client_id"],
            "project_id": st.secrets["google"]["project_id"],
            "auth_uri": st.secrets["google"]["auth_uri"],
            "token_uri": st.secrets["google"]["token_uri"],
            "auth_provider_x509_cert_url": st.secrets["google"]["auth_provider_x509_cert_url"],
            "client_secret": st.secrets["google"]["client_secret"],
            "redirect_uris": st.secrets["google"]["redirect_uris"]
        }
    }
    with open("client_secrets.json", "w") as f:
        json.dump(client_secrets, f)
    logger.info("Client secrets file created successfully.")

# Authenticate Gmail
def authenticate_gmail():
    token_file = "token.json"
    creds = None

    # Check for existing token
    if os.path.exists(token_file):
        with open(token_file, "rb") as token:
            creds = pickle.load(token)
            logger.info("Token loaded successfully.")

    # If no valid token, start OAuth flow
    if not creds or not creds.valid:
        flow = Flow.from_client_secrets_file(
            "client_secrets.json",
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
        )
        flow.redirect_uri = st.secrets["google"]["redirect_uris"][0]
        auth_url, _ = flow.authorization_url(prompt="consent")
        st.write(f"Click [here]({auth_url}) to authorize the app.")
        auth_code = st.text_input("Enter the authorization code:")
        if auth_code:
            try:
                flow.fetch_token(code=auth_code)
                creds = flow.credentials
                with open(token_file, "wb") as token:
                    pickle.dump(creds, token)
                st.success("Authorization successful!")
                logger.info("Authorization successful!")
            except Exception as e:
                st.error(f"Authorization failed: {e}")
                logger.error("Authorization error", exc_info=True)
                return None
    return build("gmail", "v1", credentials=creds)

# Fetch emails
def fetch_emails(service):
    try:
        st.info("Fetching emails...")
        results = service.users().messages().list(userId="me", q="label:inbox").execute()
        messages = results.get("messages", [])
        if not messages:
            st.write("No emails found.")
        for msg in messages[:5]:
            email = service.users().messages().get(userId="me", id=msg["id"]).execute()
            st.write(f"Snippet: {email.get('snippet', 'No content')}")
    except Exception as e:
        st.error(f"Error fetching emails: {e}")
        logger.error("Error fetching emails", exc_info=True)

# Main app logic
if __name__ == "__main__":
    os.environ["NO_GCE_CHECK"] = "true"
    create_client_secrets_file()
    st.write("Authenticate and view your Gmail inbox.")
    if st.button("Authenticate and Fetch Emails"):
        service = authenticate_gmail()
        if service:
            fetch_emails(service)
