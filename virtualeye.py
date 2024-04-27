import sys
import subprocess
import atexit
import time
import socks  # PySocks to route requests through Tor
import socket
import ipaddress  # for CIDR ranges
from concurrent.futures import ThreadPoolExecutor  # Threading
from threading import Lock
import requests
import re

#Author: Vahe Demirkhanyan

TOR_COMMAND = 'tor'
TOR_SOCKS_PORT = 9050
tor_process = None
processed_ips = set()  # Track processed IPs to avoid duplicate results
needs_tor_restart = False  # Flag to indicate if Tor needs to be restarted
tor_restart_lock = Lock()  # Lock to control access to the Tor restart process

def is_url_valid(url):
    # Regex to validate domain names with numeric and traditional segments
    return bool(re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", url)) or \
           bool(re.match(r"^(?:[a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$", url)) or \
           bool(re.match(r"^(?:[0-9]+\.){3}[0-9]+\.[a-zA-Z]{2,}$", url))

def print_info(message):
    print(f"[INFO] {message}")

def print_warning(message):
    print(f"[WARNING] {message}")

def print_error(message):
    print(f"[ERROR] {message}")

def make_request(ip_address, api_key=None):
    if api_key:
        api_url = f"http://api.hackertarget.com/reverseiplookup/?q={ip_address}&apikey={api_key}"
    else:
        api_url = f"http://api.hackertarget.com/reverseiplookup/?q={ip_address}"
    print("Working with ", ip_address)
    try:
        response = requests.get(api_url, timeout=20)
        if response.status_code == 429:
            print(f"Rate limit exceeded for {ip_address}")
            return "fail"
        elif response.status_code == 200:
            if "No DNS A records found" in response.text.lower():
                return None
            first_line = response.text.strip().split('\n')[0]
            if is_url_valid(first_line):
                return response.text.strip()  # suc connection with data
            else:
                print("First line is not a valid URL:", response.text.lower())
                return "fail"
        else:
            print("Response status code for error:", response.status_code)
            print("This was perhaps the error: ", response.text.lower())
    except requests.RequestException as e:
        print(f"Attempt failed for {ip_address}: {e}")
    return "fail"

def restart_tor():
    global needs_tor_restart, tor_process
    with tor_restart_lock:
        if needs_tor_restart:  # Check if another thread has already restarted Tor
            return  # Skip restarting if it's already done
        needs_tor_restart = True
        if tor_process:
            tor_process.terminate()
        print("Restarting Tor to change IP...")
        tor_process = subprocess.Popen(TOR_COMMAND, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(10)  # Wait for Tor to reinitialize
        setup_tor_proxy()
        print("Tor IP changed.")
        needs_tor_restart = False  # eset the flag after restarting

def start_tor():
    global tor_process
    with tor_restart_lock:
        print("Starting Tor...")
        tor_process = subprocess.Popen(TOR_COMMAND, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        atexit.register(lambda: tor_process.terminate() if tor_process else None)
        time.sleep(10)  # Wait for Tor to initialize
        print("Tor should now be ready.")
        setup_tor_proxy()

def setup_tor_proxy():
    socks.setdefaultproxy(proxy_type=socks.PROXY_TYPE_SOCKS5, addr="127.0.0.1", port=TOR_SOCKS_PORT)
    socket.socket = socks.socksocket

def make_hackertarget_request(ip_address):
    global needs_tor_restart
    api_url = f"http://api.hackertarget.com/reverseiplookup/?q={ip_address}"
    print("Working with ",ip_address)
    while True:
        try:
            with tor_restart_lock:
                if needs_tor_restart:
                    # Wait a bit for the restart to complete if another thread is restarting Tor
                    time.sleep(5)
                    continue  # Try the request again with the new Tor IP
            response = requests.get(api_url, timeout=20)
            if response.status_code == 429:  # Too Many Requests, signal for Tor restart
                print("429 code encountered. Going to restart TOR with a new IP")
                restart_tor()
                continue  # Retry with the new Tor IP
            elif "api count exceeded" in response.text.lower():
                if needs_tor_restart:
                    print(f"API count exceeded for {ip_address}, restart of TOR is in the process")
                    continue
                else:
                    print(f"API count exceeded for {ip_address}, restarting TOR")
                    restart_tor()
                    continue  # Retry with the new Tor IP
            elif response.status_code == 200:
                if "No DNS A records found" in response.text.lower():
                    return None  # Successfully connected but no records found
                first_line = response.text.strip().split('\n')[0]
                if is_url_valid(first_line):
                    return response.text.strip()  # Successful connection with data
                else:
                    print("First line is not a valid URL:", response.text.lower())
                    return "fail"

                #print(f"This was the text for {ip_address}:",response.text.strip())
                #return response.text.strip()  # Successful connection with data
            else: print("This was perhaps the error: ",response.text.lower())
        except requests.RequestException as e:
            print(f"Attempt failed for {ip_address}: {e}")
        time.sleep(5)
    #return "fail"  # Indicate a failed connection attempt after retries

def check_domain_liveliness(domain):
    try:
        socket.gethostbyname(domain)
        return domain
    except socket.gaierror:
        return None

def process_single_ip(ip_address, output_file=None, mode='tor', api_key=None):
    global processed_ips
    if ip_address not in processed_ips:  # Check if IP has already been processed
        if mode == 'tor':
            result = make_hackertarget_request(ip_address)
        else:
            result = make_request(ip_address, api_key)
        if result == "fail":
            print(f"Failed to connect to HackerTarget for IP: {ip_address}. Will retry...")
        elif result is None:
            print(f"The {ip_address} has no associated virtual hosts")
            processed_ips.add(ip_address) 
        elif result:
            processed_ips.add(ip_address)  # Mark IP as processed after a definitive response
            alive_domains = [domain for domain in result.split('\n') if domain]
            with ThreadPoolExecutor(max_workers=20) as executor:
                alive_domains = list(filter(None, executor.map(check_domain_liveliness, alive_domains)))
            if alive_domains and output_file:
                with open(output_file, 'a') as f:
                    for domain in alive_domains:
                        f.write(f"{domain}\n")
                        print(f"{ip_address} has the following virtual host:{domain}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <IP_ranges_file> [output_file] [mode] [API_key]")
        sys.exit(1)

    file_path = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    mode = sys.argv[3] if len(sys.argv) > 3 else 'direct'  # Default to using direct mode
    api_key = sys.argv[4] if len(sys.argv) > 4 else None

    if mode == 'tor':
        start_tor()

    ips_to_process = []
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if line:
                try:
                    network = ipaddress.ip_network(line, strict=False)
                    ips_to_process.extend([str(ip) for ip in network.hosts()])
                except ValueError:
                    ips_to_process.append(line)
    if mode == 'tor':
        with ThreadPoolExecutor(max_workers=5) as executor:
            args = ((ip, output_file, mode, api_key) for ip in ips_to_process)
            executor.map(lambda p: process_single_ip(*p), args)
    else:
        # Sequentially process IPs without threading for direct or API key modes
        for ip in ips_to_process:
            process_single_ip(ip, output_file, mode, api_key)

if __name__ == "__main__":
    main()
