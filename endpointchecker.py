#!/usr/bin/env python3

# # # # # # # # # # # # # # # # # # # # # # # #
# made by hitemSec
# github: https://github.com/hitem
# mastodon: @hitem@infosec.exchange 
# # # # # # # # # # # # # # # # # # # # # # # #

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style, init
import argparse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal
import sys
import time

# Disable SSL warnings (use with caution)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Initialize colorama
init()

# Global variable to handle script running status
running = True

def interpolate_color(color1, color2, factor):
    """Interpolate between two RGB colors."""
    return [int(color1[i] + (color2[i] - color1[i]) * factor) for i in range(3)]

def rgb_to_ansi(r, g, b):
    """Convert RGB to ANSI color code."""
    return f'\033[38;2;{r};{g};{b}m'

def print_logo_and_instructions():
    logo = """
  ▄ .▄▪  ▄▄▄▄▄▄▄▄ .• ▌ ▄ ·. .▄▄ · ▄▄▄ . ▄▄·  
 ██▪▐███ •██  ▀▄.▀··██ ▐███▪▐█ ▀. ▀▄.▀·▐█ ▌▪ 
 ██▀▐█▐█· ▐█.▪▐▀▀▪▄▐█ ▌▐▌▐█·▄▀▀▀█▄▐▀▀▪▄██ ▄▄ 
 ██▌▐▀▐█▌ ▐█▌·▐█▄▄▌██ ██▌▐█▌▐█▄▪▐█▐█▄▄▌▐███▌ 
 ▀▀▀ ·▀▀▀ ▀▀▀  ▀▀▀ ▀▀  █▪▀▀▀ ▀▀▀▀  ▀▀▀ ·▀▀▀  
    """
    colors = [
        (255, 0, 255),  # Purple
        (0, 0, 255)     # Blue
    ]

    num_colors = len(colors)
    rainbow_logo = ""
    color_index = 0
    num_chars = sum(len(line) for line in logo.split("\n"))
    for char in logo:
        if char != " " and char != "\n":
            factor = (color_index / num_chars) * (num_colors - 1)
            idx = int(factor)
            next_idx = min(idx + 1, num_colors - 1)
            local_factor = factor - idx
            color = interpolate_color(colors[idx], colors[next_idx], local_factor)
            rainbow_logo += rgb_to_ansi(*color) + char
            color_index += 1
        else:
            rainbow_logo += char

    instructions = f"""
    {rainbow_logo}{Style.RESET_ALL}
    {Fore.LIGHTBLACK_EX}Improve your reconnaissance by {Fore.RED}hitemSec{Style.RESET_ALL}
    {Fore.LIGHTBLACK_EX}How-To: {Fore.YELLOW}python3 endpointchecker.py -h{Style.RESET_ALL}

    {Fore.GREEN}Endpointchecker - Usage Instructions{Style.RESET_ALL}
    {Fore.YELLOW}------------------------------------{Style.RESET_ALL}
    This tool checks for specific endpoints on provided URLs.
    
    {Fore.YELLOW}Usage:{Style.RESET_ALL}
    python3 endpointchecker.py [OPTIONS]
    
    {Fore.YELLOW}Options:{Style.RESET_ALL}
    -u, --urls          Path to the URL list file
    -e, --endpoints     Path to the endpoint list file
    -o, --output        Output file for results
    -t, --timeout       Timeout for each request in seconds (default: 5)
    -w, --workers       Number of concurrent threads (default: 10)
    -r, --retries       Number of retries for each request (default: 3)
    
    {Fore.YELLOW}Examples:{Style.RESET_ALL}
    Check endpoints from a URL list:
        python3 endpointchecker.py -u urllist.txt -e endpointlist.txt -o output.txt -t 5 -w 10 -r 3

    {Fore.GREEN}Happy Recon!{Style.RESET_ALL}
    """
    print(instructions)

# Set up argument parser
parser = argparse.ArgumentParser(description='Check endpoints of URLs from provided lists.')
parser.add_argument('-u', '--urls', required=True, help='File containing list of URLs')
parser.add_argument('-e', '--endpoints', required=True, help='File containing list of endpoints')
parser.add_argument('-o', '--output', required=True, help='Output file for results')
parser.add_argument('-t', '--timeout', type=int, default=5, help='Timeout for each request in seconds')
parser.add_argument('-w', '--workers', type=int, default=10, help='Number of concurrent workers')
parser.add_argument('-r', '--retries', type=int, default=3, help='Number of retries for each request')

# Parse arguments
args = parser.parse_args()

# Read URLs from file
with open(args.urls, 'r') as file:
    urls = [line.strip() for line in file.readlines()]

# Read endpoints from file
with open(args.endpoints, 'r') as file:
    endpoints = [line.strip() for line in file.readlines()]

# Function to make a request and return the result
def check_url(url, endpoint, timeout, retries):
    # Check if URL already has 'http' or 'https' scheme
    if not url.startswith(('http://', 'https://')):
        full_url = f"https://{url}/{endpoint}"
    else:
        full_url = f"{url}/{endpoint}"
        
    full_url = full_url.rstrip('/')  # Remove trailing slash if any

    attempt = 0
    while attempt < retries:
        if not running:
            return None
        try:
            response = requests.get(full_url, timeout=timeout, verify=False)
            return full_url, response.status_code
        except requests.RequestException as e:
            attempt += 1
            if attempt == retries:
                return full_url, str(e)
            time.sleep(1)

# Function to check URLs and endpoints using multiple workers
def check_endpoints(urls, endpoints, timeout, workers, retries, output_file):
    results = defaultdict(list)
    total_requests = len(urls) * len(endpoints)
    completed_requests = 0

    with open(output_file, 'w') as file:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(check_url, url, endpoint, timeout, retries)
                for url in urls for endpoint in endpoints
            ]
            for future in as_completed(futures):
                if not running:
                    break
                result = future.result()
                if result:
                    full_url, status = result
                    results[status].append(full_url)
                    completed_requests += 1

                    # Print to terminal only if status is 200
                    if status == 200:
                        print(f"[{Fore.GREEN}{status}{Style.RESET_ALL}] {full_url}")

                    print(f"Completed {completed_requests}/{total_requests} requests", end='\r')

    return results

# Write results to file
def write_results_to_file(results, output_file):
    with open(output_file, 'w') as file:
        if 200 in results:
            file.write("[200]\n")
            for url in sorted(results[200]):
                file.write(f"{url}\n")
        for status in sorted(results.keys(), key=lambda x: (isinstance(x, int), x)):
            if status != 200:
                file.write(f"[{status}]\n")
                for url in sorted(results[status]):
                    file.write(f"{url}\n")

def signal_handler(sig, frame):
    global running
    running = False
    print("\nProcess interrupted. Exiting gracefully...")
    sys.exit(0)

# Register signal handler for SIGINT (Ctrl+C)
signal.signal(signal.SIGINT, signal_handler)

# Print logo and instructions
print_logo_and_instructions()

try:
    # Run the function and write to file
    results = check_endpoints(urls, endpoints, args.timeout, args.workers, args.retries, args.output)
    write_results_to_file(results, args.output)
except KeyboardInterrupt:
    print("\nProcess interrupted by user. Exiting...")
except Exception as e:
    print(f"\nAn error occurred: {e}")
finally:
    print("\nCleanup and exiting.")
