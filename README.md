# Endpointchecker
Endpointchecker is a Python script designed to check for specific endpoints on provided URLs. This tool enhances your reconnaissance by automating the process of verifying endpoint availability across multiple URLs.
Ive also added a basic wordlist for apiendpoints located in ```/wordlist/```.

## Features
- Multi-threaded for fast execution.
- Customizable timeout, retries, and number of concurrent workers.
- Outputs results to a file.
- Handles SSL warnings.
  
![image](https://github.com/hitem/endpointchecker/assets/8977898/ca766b11-fd95-427b-8635-b9f5290fca97)


## Installation
To run this script, you need to have Python 3 and the required packages installed. You can install the necessary packages using:
```bash
> pip install requests colorama
```

## Usage
```bash
> python3 endpointchecker.py [OPTIONS]
> python3 endpointchecker.py -h [--help]
```
### Options
- `-u, --urls`: Path to the URL list file (required).
- `-e, --endpoints`: Path to the endpoint list file (required).
- `-o, --output`: Output file for results (required).
- `-t, --timeout`: Timeout for each request in seconds (default: 5).
- `-w, --workers`: Number of concurrent threads (default: 10).
- `-r, --retries`: Number of retries for each request (default: 3).

### Examples

Check endpoints from a URL list:
```bash
> python3 endpointchecker.py -u urllist.txt -e endpointlist.txt -o output.txt -t 5 -w 10 -r 3
```

## Output
The results will be written to the specified output file, organized by HTTP status codes.

## Author
- **hitemSec**
- [GitHub](https://github.com/hitem)
- [Mastodon](https://infosec.exchange/@hitem)

## Disclaimer
Use this script with caution. Disabling SSL warnings and making numerous requests to external servers may have unintended consequences. Always have permission to test the endpoints you are checking.

---

Feel free to contribute or raise issues on [GitHub](https://github.com/hitem/endpointchecker).

Happy Recon!
