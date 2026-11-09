# Repeated Authentication Failure Triage

Repeated authentication failures can occur when a user enters an incorrect password, when an automated process uses expired credentials, or when someone repeatedly attempts to authenticate using guessed credentials.

A high number of failures from the same source within a short period should be investigated.

## Investigation

Review the affected account and source IP address.

Determine whether a successful authentication occurred shortly after the failed attempts.

Check whether multi-factor authentication was used.

Review subsequent account activity for unusual behaviour.

Determine whether the source IP is known to the organisation or normally associated with the user.

Where appropriate, confirm the activity with the account owner.

## Escalation

A successful authentication immediately following many failed attempts may increase the severity of the alert.

Escalate for further investigation when the activity cannot be explained by expected user or system behaviour.
