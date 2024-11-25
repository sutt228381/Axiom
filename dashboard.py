import os
import re
import json
import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import matplotlib.pyplot as plt

# Constants
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
TOKEN_FILE = "token.json"
CLIENT_SECRETS_FILE = "client_secrets.json"


def create_client_secrets():
    """
    Creates the client_secrets.json file using Streamlit secrets.
    """
    try:
        secrets = st.secrets["web"]
        with open(CLIENT_SECRETS_FILE, "w") as f:
            json.dump(secrets, f)
        st.info("Client secrets file created successfully.")
    except Exception as e:
        st.error(f"Error creating client_secrets.json: {e}")
        raise


def authenticate_user():
    """
    Authenticates the user using the Gmail API.
    """
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRETS_FILE, SCOPES)
            creds = flow.run_local_server(port=8080)

        with open(TOKEN_FILE, "w") as token_file:
            token_file.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)


def fetch_emails(service, query=""):
    """
    Fetch relevant emails based on the user's query.
    """
    try:
        results = service.users().messages().list(userId="me", q=query).execute()
        messages = results.get("messages", [])

        emails = []
        for message in messages[:10]:  # Limit to first 10 emails
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            snippet = msg.get("snippet", "")
            body = msg.get("payload", {}).get("body", {}).get("data", "")
            emails.append({"snippet": snippet, "body": body})

        return emails
    except Exception as e:
        st.error(f"Error fetching emails: {e}")
        return []


def extract_data_from_emails(emails):
    """
    Extract meaningful data (e.g., amounts, dates) using regex.
    """
    transactions = []
    for email in emails:
        amounts = re.findall(r"\$\d+\.?\d*", email.get("body", ""))
        dates = re.findall(r"\b(?:\d{1,2}/\d{1,2}/\d{2,4})\b", email.get("body", ""))
        transactions.append({"amounts": amounts, "dates": dates})

    return transactions


def plot_trends(transactions):
    """
    Generate a dynamic trend chart.
    """
    amounts = [float(a.strip("$")) for t in transactions for a in t["amounts"]]
    dates = [d for t in transactions for d in t["dates"]]

    fig, ax = plt.subplots()
    ax.plot(dates, amounts, marker="o")
    ax.set_title("Transaction Trends")
    ax.set_xlabel("Dates")
    ax.set_ylabel("Amounts")
    st.pyplot(fig)


def main():
    st.title("AI-Powered Email Dashboard")
    st.write("Authenticate and analyze your email inbox dynamically.")

    create_client_secrets()  # Create client_secrets.json

    email = st.text_input("Enter your email address:")
    prompt = st.text_input("Enter your query (e.g., 'Analyze TD Bank statements'): ")

    if st.button("Authenticate and Fetch Emails"):
        service = authenticate_user()
        if service:
            emails = fetch_emails(service, query=prompt)
            transactions = extract_data_from_emails(emails)

            st.write("### Extracted Data")
            st.json(transactions)

            st.write("### Trend Analysis")
            plot_trends(transactions)


if __name__ == "__main__":
    main()
