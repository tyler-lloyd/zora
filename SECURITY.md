# Security

zora runs as root on every node and handles WireGuard private keys, so
security reports are taken seriously.

## Reporting a vulnerability

Please report it privately, not in a public issue: open the repository's
**Security** tab and choose **Report a vulnerability**.

Include what you found, how to reproduce it, and what an attacker could do
with it.

## What counts

Things we especially want to hear about:

- a pod getting a tunnel, a Secret or node access it shouldn't have;
- private keys appearing in logs, events, errors or on disk;
- a pod that asked for a tunnel sending traffic outside it;
- a WireGuard config that makes the plugin or agent run commands, write
  files, or change a node's networking outside the pod;
- anything that lets one namespace affect another through zora.

## Supported versions

zora has no stable release yet. Fixes go to `main`.
