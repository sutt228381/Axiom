import os
import json
import streamlit as st
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import openai
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Paths and constants
CLIENT_SECRETS_FILE = "client_secrets.json"
TOKEN_FILE = "token.json"

# OpenAI API Key (to be added to secrets)
openai.api_key = st.secrets["openai_api_key"]

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

def fetch_emails(service, query=""):
    try:
        results = service.users().messages().list(userId="me", q=query, maxResults=20).execute()
        messages = results.get("messages", [])
        email_data = []
        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            snippet = msg.get("snippet", "No snippet available")
            email_data.append({"id": message["id"], "snippet": snippet})
        return pd.DataFrame(email_data)
    except HttpError as error:
        logger.error(f"An error occurred: {error}")
        st.error(f"An error occurred: {error}")
        return pd.DataFrame()

def analyze_emails(email_data):
    try:
        combined_snippets = " ".join(email_data["snippet"].tolist())
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a data analyst assistant."},
                {"role": "user", "content": f"Analyze the following email content: {combined_snippets}"}
            ]
        )
        return response["choices"][0]["message"]["content"]
    except Exception as e:
        logger.error(f"Error analyzing emails: {e}")
        st.error(f"Error analyzing emails: {e}")
        return None

def generate_visualizations(email_data):
    try:
        email_data["snippet_length"] = email_data["snippet"].apply(len)
        fig, ax = plt.subplots()
        ax.bar(email_data.index, email_data["snippet_length"], color="blue")
        ax.set_title("Email Snippet Lengths")
        ax.set_xlabel("Email Index")
        ax.set_ylabel("Length of Snippet")
        st.pyplot(fig)
    except Exception as e:
        logger.error(f"Error generating visualizations: {e}")
        st.error(f"Error generating visualizations: {e}")

def main():
    st.title("Enhanced Gmail Dashboard")
    email = st.text_input("Enter your email address:")
    query = st.text_input("What would you like to search for in your inbox?")
    if st.button("Authenticate and Fetch Emails"):
        creds = authenticate_user()
        if creds:
            service = build("gmail", "v1", credentials=creds)
            st.write(f"Fetching emails for query: {query}")
            email_data = fetch_emails(service, query=query)
            if not email_data.empty:
                st.write("Here are your emails:")
                for _, row in email_data.iterrows():
                    st.write(f"- {row['snippet']}")
                st.write("Analyzing emails...")
                insights = analyze_emails(email_data)
                st.write("### AI-Generated Insights:")
                st.write(insights)
                st.write("### Visualization:")
                generate_visualizations(email_data)

if __name__ == "__main__":
    main()
