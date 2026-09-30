from urllib.parse import urlparse


def validate_url(url):
    """
    Validate and normalise a user-supplied URL.

    Returns:
        (True, normalised_url, None) if valid
        (False, None, error_message) if invalid
    """

    if not url:
        return False, None, "A URL is required."

    url = url.strip()

    if len(url) > 2048:
        return False, None, "URL is too long."

    # Make the scanner easier to use.
    # example.com becomes https://example.com
    if "://" not in url:
        url = "https://" + url

    try:
        parsed_url = urlparse(url)

        if parsed_url.scheme not in ["http", "https"]:
            return False, None, "Only HTTP and HTTPS URLs are supported."

        if not parsed_url.hostname:
            return False, None, "URL must contain a valid hostname."

        # Accessing .port causes Python to validate the port
        _ = parsed_url.port

    except ValueError:
        return False, None, "The URL is malformed."

    return True, url, None