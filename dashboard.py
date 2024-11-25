import os
import json
import logging
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import streamlit as st

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Gmail API scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Authentication function
def authenticate_user():
    creds = None
    token_file = 'token.json'
    
    # Check for existing token
    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)
        logger.info("Token loaded successfully.")
    
    # If no valid token, initiate OAuth
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'client_secrets.json', SCOPES)
            creds = flow.run_local_server(port=8080)
        # Save the token
        with open(token_file, 'w') as token:
            token.write(creds.to_json())
            logger.info("Token saved successfully.")
    
    return creds

# Fetch emails
def fetch_emails(service, query=""):
    try:
        # Get messages
        response = service.users().messages().list(userId='me', q=query).execute()
        messages = response.get('messages', [])
        
        emails = []
        for message in messages[:10]:  # Limit to 10 emails
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            snippet = msg.get('snippet', '')
            emails.append({'id': message['id'], 'snippet': snippet})
        
        return emails
    except HttpError as error:
        logger.error(f"An error occurred while fetching emails: {error}")
        return []

# Fetch email details
def fetch_email_details(service, email_id):
    try:
        message = service.users().messages().get(userId='me', id=email_id).execute()
        headers = message.get('payload', {}).get('headers', [])
        subject = next((header['value'] for header in headers if header['name'] == 'Subject'), "No Subject")
        return subject, message.get('snippet', "No Snippet")
    except HttpError as error:
        logger.error(f"An error occurred while fetching email details: {error}")
        return "Error", "Could not fetch details."

# Main app logic
def main():
    st.title("Email Dashboard")
    st.write("Authenticate and fetch your emails based on search criteria.")

    # Authenticate
    creds = authenticate_user()
    if not creds:
        st.error("Authentication failed.")
        return
    
    # Build Gmail API service
    service = build('gmail', 'v1', credentials=creds)
    
    # User input for email query
    query = st.text_input("Enter a search term (e.g., 'TDBank')", "")
    
    if st.button("Fetch Emails"):
        with st.spinner("Fetching emails..."):
            emails = fetch_emails(service, query=query)
        if not emails:
            st.warning("No emails found for the given search term.")
        else:
            st.success(f"Fetched {len(emails)} emails.")
            for email in emails:
                st.subheader("Email Snippet")
                st.write(email['snippet'])
                
                if st.button(f"View Details: {email['id']}", key=email['id']):
                    subject, snippet = fetch_email_details(service, email['id'])
                    st.write(f"**Subject:** {subject}")
                    st.write(f"**Snippet:** {snippet}")

if __name__ == "__main__":
    main()
