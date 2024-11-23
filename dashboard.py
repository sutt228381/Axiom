from concurrent.futures import ThreadPoolExecutor, TimeoutError

def authenticate_with_timeout(flow, timeout=60):
    """Run the OAuth flow with a timeout."""
    with ThreadPoolExecutor() as executor:
        future = executor.submit(flow.run_local_server, port=0)
        try:
            creds = future.result(timeout=timeout)
            return creds
        except TimeoutError:
            future.cancel()
            raise TimeoutError("Authentication process timed out.")
        except Exception as e:
            raise e

def authenticate_gmail():
    """Authenticate with the Gmail API."""
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
            logger.info("Initiating OAuth flow...")
            try:
                flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
                logger.info("Opening OAuth consent screen...")
                creds = authenticate_with_timeout(flow, timeout=60)  # Use thread-based timeout
                logger.info("OAuth flow completed successfully.")
            except TimeoutError:
                logger.error("Authentication process timed out.")
                st.error("Authentication process timed out. Please try again.")
                raise TimeoutError
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
