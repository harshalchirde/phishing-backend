import re

def preprocess_url(url: str) -> str:
    """
    Cleans and normalizes URL input for phishing detection
    """

    # Convert to lowercase
    url = url.lower()

    # Remove http / https
    url = re.sub(r'^https?:\/\/', '', url)

    # Remove www
    url = re.sub(r'^www\.', '', url)

    # Remove trailing slash
    url = url.rstrip('/')

    # Keep only valid characters
    url = re.sub(r'[^a-z0-9./\-]', '', url)

    return url