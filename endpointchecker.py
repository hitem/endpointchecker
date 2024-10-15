#!/usr/bin/env python3

# # # # # # # # # # # # # # # # # # # # # # # #
# made by hitemSec
# github: https://github.com/hitem
# mastodon: @hitem@infosec.exchange 
# # # # # # # # # # # # # # # # # # # # # # # #

import aiohttp
import asyncio
import logging
from urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style, init
import argparse
from collections import defaultdict
import signal
import sys
import itertools

# Disable SSL warnings (use with caution)
import urllib3
urllib3.disable_warnings(InsecureRequestWarning)

# Initialize colorama
init()

# Setup logging to filter out specific asyncio connection reset errors
# Change between 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'. To supress all, add '+1' after CRITICAL (logging.CRITICAL+1).
logging.basicConfig(level=logging.CRITICAL)
logger = logging.getLogger("asyncio")
logger.setLevel(logging.CRITICAL)

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
    -b, --batchsize     Number of requests per batch (default: 1000)
    -s, --statuscodes   Comma-separated list of status codes to save (default: 200,500)
    
    {Fore.YELLOW}Examples:{Style.RESET_ALL}
    Check endpoints from a URL list:
        python3 endpointchecker.py -u urllist.txt -e endpointlist.txt -o output.txt -t 5 -w 10 -r 3 -s 200,500

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
parser.add_argument('-b', '--batchsize', type=int, default=1000, help='Number of requests per batch')
parser.add_argument('-s', '--statuscodes', default='200,500', help='Comma-separated list of status codes to save')

# Parse arguments
args = parser.parse_args()
statuscodes = [int(code) for code in args.statuscodes.split(',')]

# Read URLs from file
with open(args.urls, 'r') as file:
    urls = [
        (line.strip().rstrip('/') if line.startswith("http") else "https://" + line.strip().rstrip('/'))
        for line in file.readlines()
    ]

# Read endpoints from file
with open(args.endpoints, 'r') as file:
    endpoints = [line.strip().lstrip('/') for line in file.readlines()]

# Function to get the color based on the status code
def get_color(status_code):
    if 100 <= status_code < 200:
        return Fore.BLUE
    elif 200 <= status_code < 300:
        return Fore.GREEN
    elif 300 <= status_code < 400:
        return Fore.CYAN
    elif 400 <= status_code < 500:
        return Fore.RED
    elif 500 <= status_code < 600:
        return Fore.MAGENTA
    else:
        return Fore.WHITE

# Function to make a request and return the result
async def check_url(session, url, endpoint, timeout, retries):
    # Construct the full URL
    full_url = f"{url}/{endpoint}"
    
    attempt = 0
    while attempt < retries:
        if not running:
            return None
        try:
            async with session.get(full_url, timeout=timeout, ssl=False) as response:
                return full_url, response.status
        except aiohttp.ClientConnectionError:
            attempt += 1
            if attempt == retries:
                return full_url, 'Connection Error'
            await asyncio.sleep(1)
        except Exception as e:
            attempt += 1
            if attempt == retries:
                return full_url, str(e)
            await asyncio.sleep(1)

# Function to check URLs and endpoints using multiple workers in batches
async def check_endpoints_in_batches(urls, endpoints, timeout, workers, retries, output_file, batch_size):
    results = defaultdict(list)
    total_requests = len(urls) * len(endpoints)
    completed_requests = 0

    print(f"Total requests to process: {total_requests}")

    async with aiohttp.ClientSession() as session:
        with open(output_file, 'a') as file:
            for batch_start in range(0, total_requests, batch_size):
                batch_end = min(batch_start + batch_size, total_requests)
                current_batch = itertools.islice(
                    ((url, endpoint) for url in urls for endpoint in endpoints),
                    batch_start, batch_end
                )

                tasks = [
                    check_url(session, url, endpoint, timeout, retries)
                    for url, endpoint in current_batch
                ]

                for future in asyncio.as_completed(tasks):
                    if not running:
                        break
                    result = await future
                    if result:
                        full_url, status = result
                        results[status].append(full_url)
                        completed_requests += 1

                        # Print to terminal with appropriate color
                        if isinstance(status, int) and status in statuscodes:
                            color = get_color(status)
                            print(f"\r{' ' * 80}\r[{color}{status}{Style.RESET_ALL}] {full_url}")

                        # Write result to file if status is in specified status codes
                        if status in statuscodes:
                            file.write(f"[{status}] {full_url}\n")
                            file.flush()

                        # Print progress
                        print(f"\rProcessing {completed_requests} of {total_requests} requests", end='', flush=True)

    return results

# Write results to file
def write_results_to_file(output_file):
    status_groups = defaultdict(list)

    with open(output_file, 'r') as file:
        lines = file.readlines()

    # Remove status code prefixes and sort into groups
    for line in lines:
        if line.startswith('[') and ']' in line:
            status, url = line.split('] ')
            status = status[1:]
            status_groups[status].append(url.strip())

    # Remove duplicates and sort each status group
    for status in status_groups:
        status_groups[status] = sorted(set(status_groups[status]))

    # Write sorted results back to file
    with open(output_file, 'w') as file:
        for status in sorted(status_groups.keys(), key=int):
            file.write(f"[{status}]\n")
            for url in status_groups[status]:
                file.write(f"{url}\n")
            file.write("\n")

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
    loop = asyncio.get_event_loop()
    results = loop.run_until_complete(
        check_endpoints_in_batches(urls, endpoints, args.timeout, args.workers, args.retries, args.output, args.batchsize)
    )
    write_results_to_file(args.output)
except KeyboardInterrupt:
    print("\nProcess interrupted by user. Exiting...")
except Exception as e:
    print(f"\nAn error occurred: {e}")
finally:
    print("\nCleanup and exiting.")