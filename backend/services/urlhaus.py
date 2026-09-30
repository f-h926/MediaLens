import os
import requests


URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"


def check_urlhaus(url):
    """
    Check whether a URL exists in the URLhaus
    malware-distribution database.
    """

    auth_key = os.getenv("URLHAUS_AUTH_KEY")

    if not auth_key:
        return {
            "available": False,
            "error": "URLhaus Auth-Key is not configured."
        }

    headers = {
        "Auth-Key": auth_key
    }

    data = {
        "url": url
    }

    try:
        response = requests.post(
            URLHAUS_API_URL,
            headers=headers,
            data=data,
            timeout=10
        )

    except requests.RequestException:
        return {
            "available": False,
            "error": "Unable to connect to URLhaus."
        }

    if response.status_code != 200:
        return {
            "available": False,
            "error": f"URLhaus returned status {response.status_code}."
        }

    result = response.json()

    query_status = result.get("query_status")

    if query_status == "no_results":
        return {
            "available": True,
            "found": False,
            "message": "URL was not found in URLhaus."
        }

    if query_status != "ok":
        return {
            "available": False,
            "error": f"URLhaus query failed: {query_status}"
        }

    return {
        "available": True,
        "found": True,
        "url_status": result.get("url_status"),
        "threat": result.get("threat"),
        "tags": result.get("tags", []),
        "date_added": result.get("date_added")
    }