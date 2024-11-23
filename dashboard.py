def authenticate_gmail():
    """Authenticate with the Gmail API using headless flow."""
    logger.info("Starting Gmail authentication...")
    token_file = 'token.pickle'
    creds = None

    # Check if a token already exists
    if os.path.exists(token_file):
        logger.info("Loading existing token...")
        with open(token_file, 'rb') as token:
            creds = pickle.load(token)

    # If no valid token, initiate OAuth flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logger.info("Refreshing expired token...")
            creds.refresh(Request())
            logger.info("Token refreshed successfully.")
        else:
            logger.info("Initiating headless OAuth flow...")
            try:
                # Load credentials from Streamlit Secrets
                credentials = {
                    "installed": {
                        "client_id": st.secrets["gmail_client_id"],
                        "project_id": st.secrets["gmail_project_id"],
                        "auth_uri": st.secrets["gmail_auth_uri"],
                        "token_uri": st.secrets["gmail_token_uri"],
                        "auth_provider_x509_cert_url": st.secrets["gmail_auth_provider_x509_cert_url"],
                        "client_secret": st.secrets["gmail_client_secret"],
                        "redirect_uris": [st.secrets["gmail_redirect_uris"]]
                    }
                }
                flow = InstalledAppFlow.from_client_config(credentials, SCOPES)
                auth_url, _ = flow.authorization_url(prompt='consent')
                st.write("Please go to this URL to authenticate:")
                st.write(auth_url)
                st.write("Enter the authorization code below:")

                # Input box for user to paste the code
                auth_code = st.text_input("Authorization Code", key="auth_code")
                if auth_code:
                    creds = flow.fetch_token(code=auth_code)
                    logger.info("OAuth flow completed successfully.")
            except Exception as e:
                logger.error("Error during OAuth flow:", exc_info=True)
                st.error("Failed to complete OAuth authentication. Please try again.")
                raise e

        # Save the token for future use
        with open(token_file, 'wb') as token:
            pickle.dump(creds, token)
            logger.info("Token saved successfully.")

    # Build Gmail API client
    try:
        service = build('gmail', 'v1', credentials=creds)
        logger.info("Gmail API client initialized successfully.")
        return service
    except Exception as e:
        logger.error("Error initializing Gmail API client:", exc_info=True)
        st.error("Failed to initialize Gmail API client. Please check your credentials and try again.")
        raise e
