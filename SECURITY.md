# Security Policy

## Supported versions

Verum is pre-1.0. Security fixes are applied to the latest `0.x` release.

## Reporting a vulnerability

Please do not open a public issue for security problems.

Report vulnerabilities privately to **verum@ibh.group**. Include enough detail
to reproduce - the input that triggers it, the command you ran, and what you
expected. We aim to acknowledge a report within a few working days.

Because Verum reads source and infrastructure files, the reports we care about
most are: crashes or hangs on hostile input, path traversal or writes outside
the analyzed tree, and any way analysis of an untrusted repository could execute
code or exfiltrate data.
