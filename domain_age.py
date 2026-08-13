import requests
from datetime import datetime


def get_domain_age(domain):

    domain = domain.lower().strip()

    url = f"https://rdap.org/domain/{domain}"

    try:
        response = requests.get(
            url,
            timeout=10
        )

        if response.status_code != 200:
            return {
                "success": False,
                "message": "Domain registration information unavailable"
            }

        data = response.json()

        events = data.get("events", [])

        registration_date = None

        for event in events:
            if event.get("eventAction") == "registration":
                registration_date = event.get("eventDate")
                break

        if not registration_date:
            return {
                "success": False,
                "message": "Registration date unavailable"
            }

        registration_date = datetime.fromisoformat(
            registration_date.replace("Z", "+00:00")
        )

        age_days = (
            datetime.now(registration_date.tzinfo)
            - registration_date
        ).days

        return {
            "success": True,
            "age_days": age_days,
            "registration_date": registration_date.strftime(
                "%Y-%m-%d"
            )
        }

    except Exception:
        return {
            "success": False,
            "message": "Unable to retrieve domain information"
        }
