import os
import logging
import streamlit as st
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CLIENT_SECRETS_FILE = "client_secrets.json"
TOKEN_FILE = "token.json"

def create_client_secrets():
    """
    Create the client_secrets.json file dynamically from Streamlit secrets.
    """
    try:
        client_secrets_data = {
            "web": {
                "client_id": st.secrets["web"]["client_id"],
                "project_id": st.secrets["web"]["project_id"],
                "auth_uri": st.secrets["web"]["auth_uri"],
                "token_uri": st.secrets["web"]["token_uri"],
                "auth_provider_x509_cert_url": st.secrets["web"]["auth_provider_x509_cert_url"],
                "client_secret": st.secrets["web"]["client_secret"],
                "redirect_uris": st.secrets["web"]["redirect_uris"],
                "javascript_origins": st.secrets["web"]["javascript_origins"]
            }
        }
        with open(CLIENT_SECRETS_FILE, "w") as file:
            import json
            json.dump(client_secrets_data, file)
        logger.info("Client secrets file created successfully.")
    except Exception as e:
        logger.error(f"Error creating client_secrets.json: {e}")
        st.error(f"Error creating client_secrets.json: {e}")

def authenticate_user():
    """
    Authenticate the user using Gmail API.
    """
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    if not creds or not creds.valid:
        try:
            create_client_secrets()
            flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRETS_FILE, SCOPES)
            creds = flow.run_local_server(port=8080)
            with open(TOKEN_FILE, "w") as token:
                token.write(creds.to_json())
            logger.info("Authentication successful.")
        except Exception as e:
            logger.error(f"Error during authentication: {e}")
            st.error(f"Error during authentication: {e}")
    return creds

def fetch_emails(service, query):
    """
    Fetch emails from the user's Gmail inbox based on a query.
    """
    try:
        results = service.users().messages().list(userId='me', q=query, maxResults=10).execute()
        messages = results.get('messages', [])

        email_data = []
        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            snippet = msg.get('snippet', '')
            headers = {header['name']: header['value'] for header in msg['payload']['headers']}
            subject = headers.get('Subject', 'No Subject')
            date = headers.get('Date', 'No Date')
            email_data.append({'Subject': subject, 'Snippet': snippet, 'Date': date})

        return email_data
    except HttpError as error:
        logger.error(f"An error occurred: {error}")
        st.error(f"An error occurred: {error}")
        return []

def display_dashboard(emails):
    """
    Display a dashboard with the retrieved email data.
    """
    st.header("Your Gmail Dashboard")

    if emails:
        for email in emails:
            st.subheader(email['Subject'])
            st.text(f"Date: {email['Date']}")
            st.text_area("Snippet", email['Snippet'], height=100, disabled=True)
            st.divider()
    else:
        st.info("No emails to display.")

def main():
    """
    Main function to run the Streamlit app.
    """
    st.title("Gmail Email Dashboard")
    st.write("Authenticate with your Gmail account and filter emails by query.")

    query = st.text_input("Enter a query to search your emails (e.g., 'TDBank'):")

    if st.button("Authenticate and Fetch Emails"):
        creds = authenticate_user()
        if creds:
            try:
                service = build('gmail', 'v1', credentials=creds)
                if query:
                    emails = fetch_emails(service, query)
                    display_dashboard(emails)
                else:
                    st.warning("Please enter a query to search emails.")
            except Exception as e:
                logger.error(f"An error occurred: {e}")
                st.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
