# spoofcheck

A program that checks if a domain can be spoofed from. The program checks SPF and DMARC records for weak configurations that allow spoofing. 

Additionally it will alert if the domain has DMARC configuration that sends mail or HTTP requests on failed SPF/DKIM emails.

Usage:

	./spoofcheck.py [DOMAIN]
	
The program will 


## Dependencies
- `dnspython`
- `colorama`
- `emailprotectionslib`

## Setup

Simply run `pip install -r requirements.txt` from the command line to install the required dependencies.