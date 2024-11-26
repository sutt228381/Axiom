import os
import json
import logging
import streamlit as st
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import matplotlib.pyplot as plt

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Paths and constants
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
                "javascript_origins": st.secrets["web"]["javascript_origins"],
            }
        }
        with open(CLIENT_SECRETS_FILE, "w") as f:
            json.dump(client_secrets, f)
        logger.info("Client secrets file created successfully.")
    except Exception as e:
        logger.error(f"Error creating client_secrets.json: {e}")
        st.error(f"Error creating client_secrets.json: {e}")

def authenticate_user():
    create_client_secrets_file()
    try:
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
        email_snippets = []
        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            snippet = msg.get("snippet", "No snippet available")
            email_snippets.append(snippet)
        return email_snippets
    except HttpError as error:
        logger.error(f"An error occurred: {error}")
        st.error(f"An error occurred: {error}")
        return []

def analyze_emails(emails):
    categorized_data = {"Actions Needed": [], "Questions": [], "Upcoming Events": []}
    for email in emails:
        if "question" in email.lower():
            categorized_data["Questions"].append(email)
        elif "event" in email.lower() or "schedule" in email.lower():
            categorized_data["Upcoming Events"].append(email)
        else:
            categorized_data["Actions Needed"].append(email)
    return categorized_data

# Display categorized emails with visualizations
def display_dashboard(categorized_data):
    for category, items in categorized_data.items():
        st.subheader(category)
        for item in items:
            st.write(item)
        if category == "Upcoming Events":
            # Example: Visualize upcoming events in a timeline
            if items:
                st.write("Upcoming Events Timeline:")
                fig, ax = plt.subplots()
                event_dates = [f"Event {i+1}" for i in range(len(items))]
                ax.barh(event_dates, range(len(items)))
                ax.set_xlabel("Event Index")
                st.pyplot(fig)

def main():
    st.title("Gmail Dashboard")
    st.write("Enter your email address and the topic you'd like to search:")
    email = st.text_input("Email Address")
    topic = st.text_input("Search Topic (e.g., 'bank statements', 'events')")
    
    if email and st.button("Authenticate and Search"):
        creds = authenticate_user()
        if creds:
            service = build("gmail", "v1", credentials=creds)
            st.write("Authentication successful. Fetching emails...")
            emails = fetch_emails(service, topic)
            if emails:
                st.write(f"Found {len(emails)} emails.")
                categorized_data = analyze_emails(emails)
                display_dashboard(categorized_data)
            else:
                st.write("No emails found matching the query.")

if __name__ == "__main__":
    main()
