# IoC Validation

A Python tool for validating and correlating Indicators of Compromise (IoCs) using VirusTotal, AbuseIPDB, and AlienVault OTX. The script supports defanging, API error/debug logging, and outputs results to Excel.

## Features

- Defang/fang IoCs for safe handling
- Supports IPs, domains, URLs, file hashes
- Queries VirusTotal, AbuseIPDB, and OTX APIs
- Logs detailed debug info and API errors
- Exports results to Excel with verdicts
- Example input/output and test cases included

## Prerequisites

- Python 3.7+
- Obtain API keys for:
  - [VirusTotal](https://www.virustotal.com/gui/user/account/apikeys)
  - [AbuseIPDB](https://www.abuseipdb.com/account/api)
  - [AlienVault OTX](https://otx.alienvault.com/api)

## Installation

```sh
pip install -r requirements.txt
```

## Usage

1. Edit `ioc_validation.py` to insert your API keys.
2. Prepare a `.txt` or `.csv` file with IoCs (one per line or column).
3. Run:

```sh
python ioc_validation.py example_input.txt
```

4. Output will be a timestamped Excel file in the same directory.

## Example

Input (`example_input.txt`):

```
8.8.8.8
malicious[.]domain[.]com
hxxps[:]//bad[.]site
44d88612fea8a8f36de82e1278abb02f
```

Sample Output: See `example_output.xlsx`.

## Testing

Run the test:

```sh
python test_ioc_validation.py
```

## License

MIT License (see LICENSE.txt)
