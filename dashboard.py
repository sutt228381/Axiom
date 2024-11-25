import os
import json
import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

# Constants
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
TOKEN_FILE = "token.json"
CLIENT_SECRETS_FILE = "client_secrets.json"


def create_client_secrets():
    """
    Creates the client_secrets.json file using Streamlit secrets.
    """
    try:
        secrets = {
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
            json.dump(secrets, f)
        st.info("Client secrets file created successfully.")
    except Exception as e:
        st.error(f"Error creating client_secrets.json: {e}")
        raise


def authenticate_user():
    """
    Authenticates the user using the Gmail API.
    """
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRETS_FILE, SCOPES)
            auth_url, _ = flow.authorization_url(prompt="consent")
            st.write("### Authorization Required")
            st.write(f"Please go to the following URL and authorize the application: [Authorize App]({auth_url})")
            auth_code = st.text_input("Enter the authorization code:")
            if st.button("Submit Authorization Code"):
                try:
                    flow.fetch_token(code=auth_code)
                    creds = flow.credentials
                    with open(TOKEN_FILE, "w") as token_file:
                        token_file.write(creds.to_json())
                    st.success("Authentication successful!")
                except Exception as e:
                    st.error(f"Error during authentication: {e}")

    if creds:
        return build("gmail", "v1", credentials=creds)
    return None


def fetch_emails(service, query=""):
    """
    Fetch relevant emails based on the user's query.
    """
    try:
        results = service.users().messages().list(userId="me", q=query).execute()
        messages = results.get("messages", [])

        emails = []
        for message in messages[:10]:  # Limit to first 10 emails
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            snippet = msg.get("snippet", "")
            emails.append({"snippet": snippet})

        return emails
    except Exception as e:
        st.error(f"Error fetching emails: {e}")
        return []


def main():
    st.title("AI-Powered Email Dashboard")
    st.write("Authenticate and analyze your email inbox dynamically.")

    create_client_secrets()  # Create client_secrets.json

    email = st.text_input("Enter your email address:")
    prompt = st.text_input("Enter your query (e.g., 'Analyze TD Bank statements'): ")

    if st.button("Authenticate and Fetch Emails"):
        service = authenticate_user()
        if service:
            emails = fetch_emails(service, query=prompt)

            st.write("### Retrieved Emails")
            st.json(emails)


if __name__ == "__main__":
    main()
