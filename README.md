# Endpointchecker
Endpointchecker is a Python script designed to check for specific endpoints on provided URLs. This tool enhances your reconnaissance by automating the process of verifying endpoint availability across multiple URLs.
Ive also added a basic wordlist for apiendpoints located in ```/wordlist/```.

### Example: 
Input URL file: `http://example.com/` \
Input Endpoint wordlist: `api/v1` \
Url to test: `http://example.com/api/v1` 

## Features
- Multi-threaded for fast execution.
- Customizable timeout, retries, and number of concurrent workers.
- Outputs results to a file.
- Handles SSL warnings.
- Will accept URL-lists with or without https:// prefix
  
![image](https://github.com/hitem/endpointchecker/assets/8977898/37765f6d-da70-4f64-b991-c4ab7c6780ad)


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
- `-b, --batchsize`: Number of requests per batch (default: 1000).
- `-s, --statuscodes`: Which statuscodes to look for (default: 200,500).


### Examples

Check endpoints from a URL list:
```bash
> python3 endpointchecker.py -u urllist.txt -e endpointlist.txt -o output.txt -t 5 -w 10 -r 3
> python3 endpointchecker.py -u urllist.txt -e endpointlist.txt -o output.txt -t 2 -w 60 -r 2 -b 250
> python3 endpointchecker.py -u urllist.txt -e endpointlist.txt -o output.txt -t 4 -w 50 -r 1 -b 777 -s 200,301,302,500,501
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
