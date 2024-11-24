import os
import logging
import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import pickle

# List of authorized test users
AUTHORIZED_TEST_USERS = ["sortsyai@gmail.com", "adammsutton@gmail.com"]

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Gmail API scope
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Validate the user-entered email
def validate_email(user_email):
    if user_email not in AUTHORIZED_TEST_USERS:
        raise ValueError(f"Email {user_email} is not authorized. Please use a valid test email.")

# Authenticate Gmail API
def authenticate_gmail():
    token_file = "token.pickle"
    creds = None

    # Check for existing token
    if os.path.exists(token_file):
        logging.info("Loading existing token...")
        with open(token_file, "rb") as token:
            creds = pickle.load(token)

    # If no valid token, initiate OAuth flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            logging.info("Starting OAuth consent flow...")
            flow = InstalledAppFlow.from_client_secrets_file(
                "client_secrets.json", SCOPES
            )
            creds = flow.run_local_server(port=8080)
            logging.info("OAuth flow completed successfully.")

        # Save the token for future use
        with open(token_file, "wb") as token:
            pickle.dump(creds, token)
            logging.info("Token saved successfully.")

    # Build Gmail API client
    service = build("gmail", "v1", credentials=creds)
    logging.info("Gmail API client initialized successfully.")
    return service

# Fetch Emails
def fetch_emails(service, query="label:inbox"):
    logging.info(f"Fetching emails with query: {query}")
    try:
        results = service.users().messages().list(userId="me", q=query).execute()
        messages = results.get("messages", [])
        email_data = []

        if not messages:
            st.info("No emails found.")
            return email_data

        for msg in messages[:5]:  # Fetch only the first 5 emails
            email = service.users().messages().get(userId="me", id=msg["id"]).execute()
            snippet = email.get("snippet", "No content")
            email_data.append({"id": msg["id"], "snippet": snippet})

        logging.info("Emails fetched successfully.")
        return email_data

    except Exception as e:
        logging.error("Error fetching emails:", exc_info=True)
        st.error(f"An error occurred: {e}")
        return []

# Streamlit App
st.title("Gmail Dashboard")
st.write("A dashboard to view and analyze your Gmail data.")

# User email input
email = st.text_input("Enter your email address:")
if email:
    try:
        validate_email(email)
        st.success(f"Welcome, {email}!")

        if st.button("Authenticate and Fetch Emails"):
            try:
                logging.info("Starting Gmail authentication...")
                service = authenticate_gmail()
                emails = fetch_emails(service)
                if emails:
                    st.write("Fetched Emails:")
                    for email in emails:
                        st.write(f"**Snippet**: {email['snippet']}")
                        st.write("---")
                else:
                    st.info("No emails to display.")
            except Exception as e:
                logging.error("Error during email fetching.", exc_info=True)
                st.error(f"An error occurred: {e}")
    except ValueError as e:
        st.error(str(e))

# Footer
st.write("Powered by Gmail API and Streamlit.")
