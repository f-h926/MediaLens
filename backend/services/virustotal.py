import base64
import os
import requests


VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/urls"


def create_url_id(url):
    
   # convert a URL into the unpadded URL-safe Base64 identifier for VirusTotal
    
    encoded_url = base64.urlsafe_b64encode(
        url.encode()
    ).decode()

    return encoded_url.rstrip("=")


def check_url_reputation(url):
    
    # check whether VirusTotal already has a report for the supplied URL
    
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return {
            "available": False,
            "error": "VirusTotal API key is not configured."
        }

    url_id = create_url_id(url)

    endpoint = f"{VIRUSTOTAL_API_URL}/{url_id}"

    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=10
        )

    except requests.RequestException:
        return {
            "available": False,
            "error": "Unable to connect to VirusTotal."
        }

    # if VirusTotal has never seen this URL...

    if response.status_code == 404:
        return {
            "available": True,
            "found": False,
            "message": "No existing VirusTotal report was found."
        }

    # Rate limit
    if response.status_code == 429:
        return {
            "available": False,
            "error": "VirusTotal rate limit reached."
        }

    if response.status_code != 200:
        return {
            "available": False,
            "error": f"VirusTotal returned status {response.status_code}."
        }

    data = response.json()

    attributes = data.get("data", {}).get("attributes", {})

    stats = attributes.get(
        "last_analysis_stats",
        {}
    )

    return {
        "available": True,
        "found": True,

        "stats": {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0)
        },

        "reputation": attributes.get(
            "reputation",
            0
        )
    }