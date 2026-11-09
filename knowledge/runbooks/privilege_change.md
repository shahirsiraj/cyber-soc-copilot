# Unexpected Privilege Change Triage

Administrative privileges allow an account to perform higher-impact actions and should therefore be monitored carefully.

A privilege change is not automatically malicious. Legitimate changes may occur during approved administration or maintenance.

## Investigation

Identify the account receiving elevated privileges.

Determine which user or service initiated the change.

Check whether the change corresponds to an approved request or change window.

Review the activity performed by the elevated account after the privilege change.

Check whether the account normally requires administrative privileges.

## Escalation

Unexpected administrative privilege assignment without an approved reason should receive human review.
