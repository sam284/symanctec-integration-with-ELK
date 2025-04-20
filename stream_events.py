import os
import requests
from requests.structures import CaseInsensitiveDict
import time
import json
import logging


#LOG_LEVEL = os.getenv("DEBUG", "DEBUG").upper()
os.makedirs("/app/logs", exist_ok=True)
os.makedirs("/app/output", exist_ok=True)
LOG_FILE = "/app/logs/debug.log"
OUTPUT_FILE = "/app/output/symantec.jsonl"

# Configure logging
logging.basicConfig(
    level=logging.INFO,  # Change to logging.DEBUG for more details
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),  # Log to a file
        logging.StreamHandler()            # Log to console
    ]
)


# Read environment variables
AUTH_HEADER = os.getenv("SYMC_AUTH_HEADER")
STREAM_GUID = os.getenv("SYMC_STREAM_GUID")
EVENT_TIMEOUT = int(os.getenv("EVENT_TIMEOUT", "120"))  # Default 120 seconds
TOKEN_REFRESH_INTERVAL = 3600  # Refresh token every hour


# API Endpoints
TOKEN_URL = "https://api.sep.securitycloud.symantec.com/v1/oauth2/tokens"
STREAM_URL = f"https://api.sep.securitycloud.symantec.com/v1/event-export/stream/{STREAM_GUID}/0"


def generate_access_token():
    """Generate an access token from Symantec API."""
    headers = {
        "accept": "application/json",
        "authorization": f"Basic {AUTH_HEADER}",
        "content-type": "application/x-www-form-urlencoded",
    }
    data = {"grant_type": "client_credentials"}

    try:
        logging.info("Requesting access token...")
        response = requests.post(TOKEN_URL, headers=headers, data=data)
        response.raise_for_status()
        response_data = response.json()
        access_token = response_data.get("access_token")

        if access_token:
            logging.info("Access Token generated successfully.")
            return access_token
        else:
            logging.error("Failed to retrieve access token. Response: %s", response_data)
            return None
    except requests.exceptions.RequestException as e:
        logging.error("Error while generating access token: %s", e)
        return None


def stream_events():
    """Handles streaming events, automatically reconnecting if disconnected."""
    access_token = generate_access_token()
    if not access_token:
        logging.critical("Unable to proceed without a valid access token.")
        return

    headers = CaseInsensitiveDict({
        "Content-Type": "application/json",
        "Accept": "application/x-ndjson",
        "Accept-Encoding": "gzip",
    })

    start_time = time.time()
    retry_delay = 5  # Initial retry delay
    next_token = None  # Pointer for the next event batch

    while True:
        # Refresh token every 3600 seconds or if unauthorized
        if time.time() - start_time >= TOKEN_REFRESH_INTERVAL:
            logging.info("Refreshing access token...")
            access_token = generate_access_token()
            if not access_token:
                logging.critical("Failed to renew access token. Exiting.")
                return
            start_time = time.time()

        headers["Authorization"] = f"Bearer {access_token}"
        data = json.dumps({"next": next_token}) if next_token else "{}"

        try:
            logging.info("Connecting to the event stream...")
            response = requests.post(STREAM_URL, headers=headers, data=data, stream=True, timeout=EVENT_TIMEOUT)
            response.raise_for_status()

            logging.info("Connection established. Listening for events...")

            with open(OUTPUT_FILE, "a") as file:
                for line in response.iter_lines(decode_unicode=True):
                    if line:
                        try:
                            event_data = json.loads(line)
                            events = event_data.get("events", [])
                            for event in events:
                                file.write(json.dumps(event) + "\n")
                                #print(f"Event received: {json.dumps(event)}")  # Optional console output

                            next_token = event_data.get("next", None)

                        except json.JSONDecodeError:
                            logging.warning("Invalid JSON received: %s", line)

            retry_delay = 5  # Reset retry delay after success

        except requests.exceptions.RequestException as e:
            if response.status_code == 401:  # Unauthorized, refresh token
                logging.warning("Unauthorized access. Refreshing token...")
                access_token = generate_access_token()
                if not access_token:
                    logging.critical("Unable to recover from authorization failure. Exiting.")
                    return
                start_time = time.time()
                continue  # Retry immediately with new token

            logging.error("Connection error: %s. Retrying in %d seconds...", e, retry_delay)
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 60)  # Exponential backoff, max 60s


# Run the event streaming process
if __name__ == "__main__":
    stream_events()
