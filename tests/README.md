# BotGate v2.4 checks

From the BotGate source directory:

```text
python3 -m py_compile botgate_proxy.py
python3 -m unittest discover -s tests -v
```

The tests use only Python's standard library, disposable temporary directories,
and loopback sockets. They do not contact a production server or download the
live feed. Process fixtures replace only the HTTP download with controlled
responses, leaving config parsing, cache replacement, listener startup, and
access checks active. Ports are assigned locally for each test.

Coverage includes managed-feed parsing, source count/HTTP length validation,
cache failures, atomic replacement, removals, exemptions, disable behavior,
one shared updater, interval conversion, retries, and shutdown. Socket/process
checks cover both listeners, ESC/star challenges, clear/home prompts,
bidirectional relay, PROXY protocol, payload rejection, timeouts, backend
unavailability, and per-IP/global connection caps.

The v2.4 production-test candidate was checked on Windows 11 with Python 3.12.14.
The actual HTTPS source was also checked separately in a disposable cache,
including validation, replacement, reload, and disabled filtering. Production
testing on unix-bit confirmed feed blocks on both listeners, hourly refreshes,
and activation of a changed upstream list. Automated tests cover removals and
failure retention separately from that owner evidence.

## GitHub Actions

The `.github/workflows/tests.yml` runs syntax checks and this test suite
on Linux, Windows, and macOS using Python 3.12. It runs on branch pushes and pull
requests, and supports manual runs after it is available on the default branch.
Each platform reports independently, so one failure does not cancel the others.
The workflow only tests code; it does not deploy, push, tag, or publish releases.
Python 3.12 coverage does not establish compatibility with every older Python
version advertised in the user guide.

Review the GitHub-hosted results for each platform separately from local checks
and owner production testing; none of these substitutes for the others.
