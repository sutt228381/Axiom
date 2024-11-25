import os
import json
import logging
from datetime import datetime
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import streamlit as st
from openai import ChatCompletion
import matplotlib.pyplot as plt

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Gmail API scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Authenticate user
def authenticate_user():
    creds = None
    token_file = 'token.json'

    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)

    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file('client_secrets.json', SCOPES)
        creds = flow.run_local_server(port=8080)

        with open(token_file, 'w') as token:
            token.write(creds.to_json())

    return creds

# Fetch emails
def fetch_emails(service, query=""):
    try:
        response = service.users().messages().list(userId='me', q=query).execute()
        messages = response.get('messages', [])
        
        emails = []
        for message in messages[:10]:  # Limit to 10 emails
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            snippet = msg.get('snippet', '')
            emails.append(snippet)
        
        return emails
    except HttpError as error:
        logger.error(f"An error occurred while fetching emails: {error}")
        return []

# Analyze and organize emails
def analyze_emails(emails):
    categorized_data = {
        "Actions Needed": [],
        "Questions": [],
        "Upcoming Events": [],
    }

    for email in emails:
        # Use AI to categorize the email
        response = ChatCompletion.create(
            model="gpt-4",
            messages=[
                {
                    "role": "system",
                    "content": "You are an assistant that categorizes emails based on their content into three categories: 'Actions Needed', 'Questions', and 'Upcoming Events'. Provide concise categorizations."
                },
                {"role": "user", "content": email}
            ]
        )
        category = response['choices'][0]['message']['content']

        if "Actions Needed" in category:
            categorized_data["Actions Needed"].append(email)
        if "Questions" in category:
            categorized_data["Questions"].append(email)
        if "Upcoming Events" in category:
            categorized_data["Upcoming Events"].append(email)

    return categorized_data

# Display timeline for upcoming events
def display_timeline(upcoming_events):
    dates = []
    descriptions = []

    for event in upcoming_events:
        try:
            # Extract the first date mentioned in the event
            response = ChatCompletion.create(
                model="gpt-4",
                messages=[
                    {
                        "role": "system",
                        "content": "Extract the first date mentioned in the following text and return it in YYYY-MM-DD format. If no date is found, say 'None'."
                    },
                    {"role": "user", "content": event}
                ]
            )
            date = response['choices'][0]['message']['content']
            if date != "None":
                dates.append(datetime.strptime(date, "%Y-%m-%d"))
                descriptions.append(event[:50] + "...")  # Add a snippet of the event
        except Exception as e:
            logger.error(f"Error parsing date from event: {e}")

    if dates:
        # Plot timeline
        plt.figure(figsize=(10, 5))
        plt.scatter(dates, [1] * len(dates), color='blue', marker='o')
        plt.yticks([])
        for i, (date, desc) in enumerate(zip(dates, descriptions)):
            plt.text(date, 1.01, desc, rotation=45, ha='right')
        st.pyplot(plt)
    else:
        st.write("No upcoming events found.")

# Main app
def main():
    st.title("AI-Powered Email Dashboard")
    st.write("Fetch and analyze your emails using AI to organize actionable insights.")

    creds = authenticate_user()
    if not creds:
        st.error("Authentication failed.")
        return
    
    service = build('gmail', 'v1', credentials=creds)
    query = st.text_input("Enter a search term (e.g., 'TDBank')", "")
    
    if st.button("Fetch and Analyze Emails"):
        with st.spinner("Fetching and analyzing emails..."):
            emails = fetch_emails(service, query=query)
            if not emails:
                st.warning("No emails found for the given search term.")
                return

            categorized_data = analyze_emails(emails)
        
        st.subheader("Actions Needed")
        for action in categorized_data["Actions Needed"]:
            st.write(action)
        
        st.subheader("Questions")
        for question in categorized_data["Questions"]:
            st.write(question)

        st.subheader("Upcoming Events")
        display_timeline(categorized_data["Upcoming Events"])

if __name__ == "__main__":
    main()
