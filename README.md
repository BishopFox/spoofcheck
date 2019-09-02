# spoofcheck

**Forked from https://github.com/BishopFox/spoofcheck**

## Differences from original
- code refactoring
- port to python3
- Dockerfile

## About

A program that checks if a domain can be spoofed from. The program checks SPF and DMARC records for weak configurations that allow spoofing. 

Additionally it will alert if the domain has DMARC configuration that sends mail or HTTP requests on failed SPF/DKIM emails.

Usage:

`./spoofcheck.py [DOMAIN]`

Domains are spoofable if any of the following conditions are met:
- Lack of an SPF or DMARC record
- SPF record never specifies `~all` or `-all`
- DMARC policy is set to `p=none` or is nonexistent


## Dependencies
- `dnspython`
- `colorama`
- `py-emailprotection`
- `tldextract`

## Setup

Run `pip install -r requirements.txt` from the command line to install the required dependencies.

## Docker setup

```
docker build -t spoofcheck .
docker run -it --rm spoofcheck [domain]
```

## Thanks

https://github.com/BishopFox
