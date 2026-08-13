import os
import requests


def check_reputation(url):

    api_key = os.getenv("SCAMSHIELD_API_KEY")

    if not api_key:
        return {
            "available": False,
            "message": "Reputation service not configured"
        }

    # External reputation provider can be connected here.

    return {
        "available": False,
        "message": "Reputation lookup not implemented yet"
    }
