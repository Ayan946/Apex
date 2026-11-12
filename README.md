# apex

A CLI-driven API security scanner testing REST APIs against the OWASP API Security Top 10. Maps the attack surface before testing — then runs targeted checks for broken auth, weak JWT secrets, IDOR, mass assignment, and more.

## Features

- Attack surface discovery — probes common API paths and checks allowed HTTP methods
- Broken Object Level Authorization (IDOR) — API1:2023
- Broken Authentication + weak JWT secret detection — API2:2023
- Mass Assignment detection — API3:2023
- Excessive Data Exposure — API3:2023
- No Rate Limiting — API4:2023
- Broken Function Level Authorization — API5:2023
- Server Side Request Forgery — API7:2023
- Injection (SQLi) detection
- Security Misconfiguration — missing headers, HTTP vs HTTPS
- Clean, progressive nuclei-style terminal output
- Optional output file saving

## Installation

```bash
git clone https://github.com/Ayan946/Apex.git
cd Apex
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## Usage

```bash
apex -t http://target.com/api/endpoint
```

Save output to a file:
```bash
apex -t http://target.com/api/endpoint -o results.txt
```

## Help

```bash
apex --help
```


## OWASP API Top 10 Coverage

| Category | Status |
|----------|--------|
| API1:2023 Broken Object Level Authorization | ✅ |
| API2:2023 Broken Authentication | ✅ |
| API3:2023 Broken Object Property Level Authorization | ✅ |
| API4:2023 Unrestricted Resource Consumption | ✅ |
| API5:2023 Broken Function Level Authorization | ✅ |
| API6:2023 Unrestricted Access to Sensitive Business Flows | ⚠️ Not yet implemented |
| API7:2023 Server Side Request Forgery | ✅ |
| API8:2023 Security Misconfiguration | ✅ |
| API9:2023 Improper Inventory Management | ✅ (via discovery module) |
| API10:2023 Unsafe Consumption of APIs | ⚠️ Not yet implemented |

## Tests

Smoke tests cover the baseline-gated checks (auth bypass, JWT, IDOR, BFLA) to guard against false positives:

```bash
python3 test_apex.py
```

## Disclaimer

For authorized security testing only.
