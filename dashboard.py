import os
import json
import streamlit as st
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import openai
import logging
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# OpenAI API Key
openai.api_key = st.secrets["openai_api_key"]

# Paths and constants
TOKEN_FILE = "token.json"

def authenticate_user():
    """Authenticate Gmail API using OAuth2."""
    try:
        flow = Flow.from_client_config(
            st.secrets["web"],
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
        )
        flow.redirect_uri = st.secrets["web"]["redirect_uris"][0]

        auth_url, _ = flow.authorization_url(prompt="consent")
        st.write(f"[Click here to authenticate]({auth_url})")

        code = st.experimental_get_query_params().get("code")
        if code:
            flow.fetch_token(code=code[0])
            creds = flow.credentials
            with open(TOKEN_FILE, "w") as token_file:
                token_file.write(creds.to_json())
            logger.info("Authentication successful.")
            return creds
    except Exception as e:
        logger.error(f"Error during Gmail authentication: {e}")
        st.error(f"Error during Gmail authentication: {e}")
        return None

def fetch_emails(service, query):
    """Fetch emails based on the user query."""
    try:
        results = service.users().messages().list(userId="me", q=query, maxResults=10).execute()
        messages = results.get("messages", [])
        email_data = []
        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            snippet = msg.get("snippet", "No snippet available")
            date = datetime.fromtimestamp(int(msg["internalDate"]) / 1000)
            email_data.append({"Snippet": snippet, "Date": date})
        return email_data
    except HttpError as error:
        logger.error(f"An error occurred: {error}")
        st.error(f"An error occurred: {error}")
        return []

def analyze_emails_with_openai(emails, user_query):
    """Analyze emails using OpenAI."""
    try:
        if not emails:
            st.warning("No emails to analyze.")
            return "No emails to analyze."
        
        prompt = (
            f"The user query is: '{user_query}'. Below are email snippets fetched from their inbox:\n\n"
            + "\n".join(email["Snippet"] for email in emails)
            + "\n\nBased on the query, analyze the email data and provide a meaningful summary, "
            + "insights, or trends. Suggest actions if applicable."
        )

        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",  # or "gpt-4" if you have access
            messages=[
                {"role": "system", "content": "You are an AI assistant that analyzes email data."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=1000,
        )
        analysis = response["choices"][0]["message"]["content"]
        return analysis
    except Exception as e:
        logger.error(f"Error analyzing emails with OpenAI: {e}")
        st.error(f"Error analyzing emails: {e}")
        return None

def display_dashboard(email_data, analysis):
    """Display a dashboard based on the email data and analysis."""
    try:
        st.header("AI Analysis")
        st.write(analysis)

        st.header("Visualizations")
        if not email_data:
            st.warning("No data to visualize.")
            return
        
        df = pd.DataFrame(email_data)
        df["Date"] = pd.to_datetime(df["Date"])
        
        # Emails over time
        emails_over_time = df.set_index("Date").resample("D").size()
        st.subheader("Emails Over Time")
        plt.figure(figsize=(10, 6))
        plt.plot(emails_over_time.index, emails_over_time.values, marker="o")
        plt.xlabel("Date")
        plt.ylabel("Number of Emails")
        plt.title("Email Activity Over Time")
        st.pyplot(plt)
    except Exception as e:
        logger.error(f"Error creating visualizations: {e}")
        st.error(f"Error creating visualizations: {e}")

def main():
    st.title("AI-Powered Gmail Dashboard")
    st.write("Authenticate and analyze your Gmail inbox.")

    user_query = st.text_input("What are you looking for in your emails?")
    if not user_query:
        st.warning("Please enter a search query.")
        return

    creds = authenticate_user()
    if creds:
        service = build("gmail", "v1", credentials=creds)
        st.write("Authentication successful. Fetching emails...")
        email_data = fetch_emails(service, user_query)
        
        if email_data:
            analysis = analyze_emails_with_openai(email_data, user_query)
            display_dashboard(email_data, analysis)
        else:
            st.warning("No emails found for the query.")

if __name__ == "__main__":
    main()
