# Unusual Outbound Data Transfer Triage

Large outbound transfers may represent normal business activity such as backups, data synchronisation or approved file transfers.

Large transfer size alone is not sufficient evidence of malicious activity.

## Investigation

Review the source system and user responsible for the transfer.

Determine whether the destination is known and trusted.

Compare the transfer volume against the historical behaviour of the system.

Check whether the transfer occurred during an expected business or backup window.

Review related authentication and system activity.

## Escalation

A large transfer to an unknown destination without an expected business explanation should receive further investigation.
