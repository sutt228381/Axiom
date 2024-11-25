import os
import json
import streamlit as st
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import logging
import openai  # Import OpenAI library
import matplotlib.pyplot as plt

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Paths and constants
CLIENT_SECRETS_FILE = "client_secrets.json"
TOKEN_FILE = "token.json"

# Set up OpenAI API key
openai.api_key = st.secrets["openai"]["api_key"]

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

def fetch_emails(service):
    try:
        results = service.users().messages().list(userId="me", labelIds=["INBOX"], maxResults=10).execute()
        messages = results.get("messages", [])
        emails = []
        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            snippet = msg.get("snippet", "No snippet available")
            emails.append(snippet)
        return emails
    except HttpError as error:
        logger.error(f"An error occurred: {error}")
        st.error(f"An error occurred: {error}")
        return []

def analyze_emails_with_openai(emails):
    try:
        prompt = "Summarize the following emails into categories like 'Action Needed', 'Upcoming Events', and 'Other':\n\n"
        prompt += "\n\n".join(emails)
        response = openai.Completion.create(
            engine="text-davinci-003",
            prompt=prompt,
            max_tokens=300,
            n=1,
            stop=None,
            temperature=0.7,
        )
        return response.choices[0].text.strip()
    except Exception as e:
        logger.error(f"Error analyzing emails: {e}")
        st.error(f"Error analyzing emails: {e}")
        return "Could not analyze emails."

def visualize_email_data(emails):
    try:
        categories = {"Action Needed": 0, "Upcoming Events": 0, "Other": 0}
        for email in emails:
            if "Action" in email:
                categories["Action Needed"] += 1
            elif "Event" in email:
                categories["Upcoming Events"] += 1
            else:
                categories["Other"] += 1
        
        # Plot data
        fig, ax = plt.subplots()
        ax.bar(categories.keys(), categories.values())
        ax.set_title("Email Categories")
        ax.set_ylabel("Count")
        st.pyplot(fig)
    except Exception as e:
        logger.error(f"Error visualizing email data: {e}")
        st.error(f"Error visualizing email data: {e}")

def main():
    st.title("Gmail Dashboard with Visualizations")
    creds = authenticate_user()
    if creds:
        service = build("gmail", "v1", credentials=creds)
        st.write("Authentication successful. Fetching emails...")
        emails = fetch_emails(service)
        if emails:
            st.write("Analyzing emails...")
            analysis = analyze_emails_with_openai(emails)
            st.write("Email Analysis:")
            st.write(analysis)
            st.write("Visualizing email data...")
            visualize_email_data(emails)

if __name__ == "__main__":
    main()
