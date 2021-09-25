# ClamAV Security Policy

If you are unsure if your bug is a security issue, please report it as a security issue.

> `*`Bytecode signatures are cross-platform executable plugins. ClamAV will not load bytecode signatures unless they are signed by Cisco-Talos or the user has intentionally enabled unsigned bytecode signatures. Issues that require disabling this security mechanism and then loading unsigned bytecode signatures or loading unsigned bytecode signatures with the ClamBC signature testing tool are not considered to be vulnerabilities.

## Vulnerability reporting best practices.

Do **not** discuss the issue in a public forum, the project mailing lists, in chat, or anywhere else.

Do **not** create a ticket on GitHub Issues. GitHub Issues are public. Submitting any information there on how to exploit ClamAV puts the ClamAV community at risk. If you do report a vulnerability via GitHub issues, your issue will be promptly removed.

Submit your report by email to psirt@cisco.com. Support requests submitted to Cisco PSIRT that are received via email are typically acknowledged within 48 hours. PSIRT will provide you with additional information on how to proceed. Cisco PSIRT will work with the ClamAV developers to confirm or reject the security vulnerability.

If the report is rejected, PSIRT or the ClamAV developers will write to you to explain why.

If the report is accepted, the ClamAV team will craft a fix and may request your help to verify that you find it satisfactory. Cisco will assign a CVE ID and will work with you to identify a disclosure date when the CVE summary will become public and when it will be safe to discuss in public.

Please allow us at least 90 days (about 3 months) to craft a fix and publish a security patch version with the fix before you tell anyone else about it. This non-disclosure window is critical to the security of your fellow ClamAV users and to the security of other products using libclamav.

## How do I submit my vulnerability report?

Security issues should be reported to Cisco PSIRT. The recommended method is to submit in email form to psirt@cisco.com. For details, see: https://tools.cisco.com/security/center/resources/security_vulnerability_policy.html

## What should I include in my vulnerability report?

Follow the same best practices for reporting a regular bug, but do not submit it on GitHub Issues! Instead, craft an email with the detailed report and attached files and submit it to psirt@cisco.com.

First, verify that the bug exists in the latest stable patch release. This may not be the latest release provided by your package manager.

At a minimum include the following:

- Include step-by-step instructions for how to reproduce the issue.

- If the issue is triggered by scanning a specific file, either:

  - Include the file in an encrypted zip along with the password.

  - Include instructions for how to generate a file that can be used to reproduce the issue.

- Describe your working environment.
