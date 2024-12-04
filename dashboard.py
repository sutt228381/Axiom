import os
import json
import pandas as pd
import streamlit as st
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import openai
from datetime import datetime

# Paths and constants
CLIENT_SECRETS_FILE = "client_secrets.json"
TOKEN_FILE = "token.json"

# OpenAI API Key
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
            }
        }
        with open(CLIENT_SECRETS_FILE, "w") as f:
            json.dump(client_secrets, f)
        st.success("Client secrets file created successfully.")
    except Exception as e:
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
        st.markdown(f"[Click here to authenticate]({auth_url})")

        code = st.experimental_get_query_params().get("code")
        if code:
            flow.fetch_token(code=code[0])
            creds = flow.credentials
            with open(TOKEN_FILE, "w") as token:
                token.write(creds.to_json())
            st.success("Authentication successful!")
            return creds
    except Exception as e:
        st.error(f"Error during Gmail authentication: {e}")
        return None

def fetch_emails(service, query):
    try:
        results = service.users().messages().list(userId="me", q=query, maxResults=50).execute()
        messages = results.get("messages", [])
        email_data = []
        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            snippet = msg.get("snippet", "No snippet available")
            headers = msg["payload"]["headers"]
            date = next((h["value"] for h in headers if h["name"] == "Date"), None)
            email_data.append({"Date": date, "Snippet": snippet})
        return email_data
    except HttpError as error:
        st.error(f"An error occurred: {error}")
        return []

def analyze_emails_with_ai(emails, user_query):
    combined_text = " ".join([email["Snippet"] for email in emails])
    prompt = f"""
    You are an intelligent assistant. Analyze the following email data and respond to the user query:
    User Query: {user_query}
    Email Data: {combined_text}
    Provide an organized summary, including any trends, key insights, and structured data.
    """
    try:
        response = openai.Completion.create(
            engine="text-davinci-003",
            prompt=prompt,
            max_tokens=1000,
            temperature=0.7,
        )
        return response["choices"][0]["text"].strip()
    except Exception as e:
        st.error(f"Error analyzing emails: {e}")
        return None

def display_dashboard(analysis, emails):
    st.subheader("AI Analysis")
    st.write(analysis)

    st.subheader("Visualizations")
    try:
        email_df = pd.DataFrame(emails)
        email_df["Date"] = pd.to_datetime(email_df["Date"], errors="coerce")
        email_df = email_df.dropna(subset=["Date"])

        # Group emails by month for visualization
        monthly_counts = email_df.resample("M", on="Date").size()
        st.bar_chart(monthly_counts)
    except Exception as e:
        st.error(f"Error creating visualizations: {e}")

def main():
    st.title("AI-Powered Gmail Dashboard")
    st.write("Authenticate and analyze your Gmail inbox.")

    user_query = st.text_input("What are you looking for in your emails?")

    if user_query:
        creds = authenticate_user()
        if creds:
            service = build("gmail", "v1", credentials=creds)
            st.write("Authentication successful. Fetching emails...")
            emails = fetch_emails(service, user_query)
            if emails:
                analysis = analyze_emails_with_ai(emails, user_query)
                display_dashboard(analysis, emails)

if __name__ == "__main__":
    main()
