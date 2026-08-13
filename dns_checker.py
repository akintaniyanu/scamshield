import dns.resolver


def check_dns(domain):

    result = {
        "a": False,
        "mx": False,
        "ns": False,
        "txt": False
    }

    records = {
        "a": "A",
        "mx": "MX",
        "ns": "NS",
        "txt": "TXT"
    }

    for key, record_type in records.items():

        try:
            dns.resolver.resolve(
                domain,
                record_type
            )

            result[key] = True

        except Exception:
            result[key] = False

    return result
