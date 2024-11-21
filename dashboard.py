import os
os.environ["STREAMLIT_SERVER_HEADLESS"] = "true"

import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import pickle
from google.auth.transport.requests import Request

# Define Gmail API Scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Authenticate Gmail API
def authenticate_gmail():
    token_file = os.path.join(os.getcwd(), 'token.pickle')
    creds = None

    # Load existing token if available
    if os.path.exists(token_file):
        with open(token_file, 'rb') as token:
            creds = pickle.load(token)

    # If no valid token, log in and save token
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('client_secret_1059524177486-6pkol5que1iejjnmmse9keqjgmiq2pqp.apps.googleusercontent.com.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the token for future use
        with open(token_file, 'wb') as token:
            pickle.dump(creds, token)

    # Build the Gmail API client
    service = build('gmail', 'v1', credentials=creds)
    return service

# Fetch Emails
def fetch_emails(service, query="label:inbox"):
    # Search for emails based on the query
    results = service.users().messages().list(userId='me', q=query).execute()
    messages = results.get('messages', [])
    email_data = []
    if not messages:
        st.write("No emails found.")
        return email_data
    for msg in messages[:5]:  # Fetch only the first 5 emails
        email = service.users().messages().get(userId='me', id=msg['id']).execute()
        snippet = email.get('snippet', 'No content')  # Extract email snippet
        email_data.append({
            'id': msg['id'],
            'snippet': snippet,
            'internalDate': email.get('internalDate'),
            'payload': email.get('payload', {}).get('headers', [])
        })
    return email_data

# Streamlit App
st.title("Gmail Dashboard")
st.write("A dashboard to view and analyze your Gmail data.")

# Button to trigger email fetching
if st.button("Fetch Emails"):
    try:
        st.write("Authenticating with Gmail...")
        service = authenticate_gmail()  # Authenticate Gmail API
        st.write("Fetching emails...")
        emails = fetch_emails(service)  # Fetch emails
        if emails:
            st.write("Fetched Emails:")
            for email in emails:
                st.write(f"**ID**: {email['id']}")
                st.write(f"**Snippet**: {email['snippet']}")
                st.write("---")
    except Exception as e:
        st.error(f"An error occurred: {e}")

# Footer
st.write("Powered by Gmail API and Streamlit.")
