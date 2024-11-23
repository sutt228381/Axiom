import os
import logging
import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import pickle

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Gmail API Scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Set Google Cloud Project (explicitly set the project ID)
os.environ["GOOGLE_CLOUD_PROJECT"] = "concise-rex-442402-b5"
os.environ["NO_GCE_CHECK"] = "true"

# Authenticate Gmail
def authenticate_gmail():
    logger.info("Starting Gmail authentication...")
    creds = None
    token_file = "token.pickle"

    # Check if token file exists
    if os.path.exists(token_file):
        with open(token_file, 'rb') as token:
            creds = pickle.load(token)

    # If credentials are invalid or missing, run OAuth flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            logger.info("Starting OAuth consent flow...")
            try:
                flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
                flow.redirect_uri = 'https://axiomgit-dppnbnhmqnccrv4xcjm3r3.streamlit.app/'
                
                # Use run_console() to avoid needing a browser
                auth_url, _ = flow.authorization_url(prompt='consent')
                st.write("Go to the following URL, authorize the app, and paste the resulting code below:")
                st.write(auth_url)

                # Get user input for authorization code
                auth_code = st.text_input("Enter the authorization code:", "")
                if st.button("Submit Authorization Code"):
                    creds = flow.fetch_token(code=auth_code)
                    st.success("Authentication successful!")
                    logger.info("Authentication successful.")
                else:
                    st.warning("Please enter the authorization code.")

            except Exception as e:
                logger.error(f"Error during OAuth flow: {e}")
                st.error(f"An error occurred during authentication: {e}")
                return None

        # Save credentials for future use
        with open(token_file, 'wb') as token:
            pickle.dump(creds, token)
            logger.info("Token saved successfully.")

    # Initialize Gmail API service
    try:
        service = build('gmail', 'v1', credentials=creds)
        logger.info("Gmail API client initialized successfully.")
        return service
    except Exception as e:
        logger.error(f"Error initializing Gmail API client: {e}")
        st.error(f"An error occurred initializing Gmail API: {e}")
        return None

# Fetch emails
def fetch_emails(service, query="label:inbox"):
    try:
        logger.info(f"Fetching emails with query: {query}")
        results = service.users().messages().list(userId='me', q=query).execute()
        messages = results.get('messages', [])
        email_data = []
        for msg in messages[:5]:  # Fetch only the first 5 emails
            email = service.users().messages().get(userId='me', id=msg['id']).execute()
            snippet = email.get('snippet', 'No content')
            email_data.append({
                'id': msg['id'],
                'snippet': snippet,
            })
        return email_data
    except Exception as e:
        logger.error(f"Error fetching emails: {e}")
        st.error(f"An error occurred fetching emails: {e}")
        return []

# Streamlit app
st.title("Gmail Dashboard")
st.write("A dashboard to view and analyze your Gmail data.")

# Button to trigger email authentication and fetching
if st.button("Authenticate and Fetch Emails"):
    service = authenticate_gmail()
    if service:
        st.info("Fetching emails...")
        emails = fetch_emails(service)
        if emails:
            st.success("Emails fetched successfully!")
            for email in emails:
                st.write(f"**Snippet:** {email['snippet']}")
        else:
            st.warning("No emails found.")

# Button to display logs
if st.button("Show Logs"):
    try:
        with open("app.log", "r") as log_file:
            st.text(log_file.read())
    except Exception as e:
        st.error(f"Error reading log file: {e}")

# Footer
st.write("Powered by Gmail API and Streamlit.")
