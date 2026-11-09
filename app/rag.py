import json

from app.models import SecurityAlert


def build_alert_query(
    alert: SecurityAlert,
) -> str:

    details = json.dumps(
        alert.details,
        sort_keys=True,
    )

    return (
        f"Alert type: "
        f"{alert.alert_type}\n"

        f"Severity: "
        f"{alert.severity}\n"

        f"Summary: "
        f"{alert.summary}\n"

        f"Details: "
        f"{details}"
    )