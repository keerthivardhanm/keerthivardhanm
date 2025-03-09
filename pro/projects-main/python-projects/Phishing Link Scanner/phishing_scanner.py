import sys
import socket
import requests
import whois
from urllib.parse import urlparse
from datetime import datetime
import argparse
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class TerminalPhishingScanner:
    def __init__(self, api_keys=None):
        self.api_keys = api_keys or {}
        self.scan_history = []

    def print_banner(self):
        print(Fore.CYAN + r"""
         ____  _     _     _     ____  _   _ ____  
        |  _ \| |__ (_)___| |__ / ___|| | | |  _ \ 
        | |_) | '_ \| / __| '_ \\___ \| |_| | | | |
        |  __/| | | | \__ \ | | |___) |  _  | |_| |
        |_|   |_| |_|_|___/_| |_|____/|_| |_|____/ 
        """ + Style.RESET_ALL)
        print(Fore.YELLOW + "Terminal Phishing Link Scanner v2.0")
        print("=======================================" + Style.RESET_ALL)

    def run_scan(self, url):
        try:
            print(Fore.GREEN + f"\nStarting scan for: {url}" + Style.RESET_ALL)
            results = []
            
            parsed = self.validate_url(url)
            results.extend(self.check_https(parsed))
            results.extend(self.check_url_shorteners(parsed))
            results.extend(self.check_suspicious_keywords(parsed))
            results.extend(self.check_dnsbl(parsed.netloc))
            results.extend(self.check_domain_age(parsed.netloc))
            results.extend(self.check_homoglyphs(url))
            
            if self.api_keys.get('virustotal'):
                results.extend(self.check_virustotal(url))
            
            self.display_results(results)
            self.scan_history.append({
                'timestamp': datetime.now(),
                'url': url,
                'results': results
            })
            
            return results

        except Exception as e:
            print(Fore.RED + f"\nError: {str(e)}" + Style.RESET_ALL)
            return []

    def validate_url(self, url):
        parsed = urlparse(url)
        if not parsed.scheme:
            parsed = urlparse(f"http://{url}")
        if not parsed.netloc:
            raise ValueError("Invalid URL format")
        return parsed

    # Security Check Methods
    def check_https(self, parsed_url):
        https = parsed_url.scheme == 'https'
        return [{
            'check': 'HTTPS',
            'status': 'Secure' if https else 'Warning',
            'message': 'Encrypted connection' if https else 'No encryption'
        }]

    def check_url_shorteners(self, parsed_url):
        shorteners = {'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 
                     'buff.ly', 'adf.ly', 'shorte.st', 'tiny.cc', 'bit.do'}
        domain = parsed_url.netloc
        if any(short in domain for short in shorteners):
            return [{
                'check': 'URL Shortener',
                'status': 'Warning',
                'message': 'Known shortening service detected'
            }]
        return [{
            'check': 'URL Shortener',
            'status': 'Safe',
            'message': 'No shorteners detected'
        }]

    def check_suspicious_keywords(self, parsed_url):
        keywords = ['login', 'signin', 'verify', 'account', 'bank',
                   'paypal', 'secure', 'update', 'password', 'credit']
        url_path = (parsed_url.path + parsed_url.query).lower()
        found = [kw for kw in keywords if kw in url_path]
        if found:
            return [{
                'check': 'Suspicious Keywords',
                'status': 'Warning',
                'message': f'Found: {", ".join(found)}'
            }]
        return [{
            'check': 'Keywords',
            'status': 'Safe',
            'message': 'No suspicious keywords'
        }]

    def check_dnsbl(self, domain):
        try:
            reversed_domain = '.'.join(reversed(domain.split('.')))
            dbl_query = f"{reversed_domain}.dbl.spamhaus.org"
            socket.gethostbyname_ex(dbl_query)
            return [{
                'check': 'DNS Blacklist',
                'status': 'Danger',
                'message': 'Blocklisted in Spamhaus DBL'
            }]
        except socket.gaierror:
            return [{
                'check': 'DNS Blacklist',
                'status': 'Safe',
                'message': 'Not in blacklist'
            }]
        except Exception as e:
            return [{
                'check': 'DNS Check',
                'status': 'Error',
                'message': str(e)
            }]

    def check_domain_age(self, domain):
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                
            age = (datetime.now() - creation_date).days
            status = 'New Domain (<1 year)' if age < 365 else 'Established Domain'
            return [{
                'check': 'Domain Age',
                'status': status,
                'message': f'{age} days old'
            }]
        except:
            return [{
                'check': 'Domain Age',
                'status': 'Error',
                'message': 'Could not retrieve domain info'
            }]

    def check_homoglyphs(self, url):
        homoglyphs = ['å', 'ä', 'ö', 'ã', 'ê', 'æ', 'ø', 'ñ']
        found = [char for char in url if char in homoglyphs]
        if found:
            return [{
                'check': 'Homoglyphs',
                'status': 'Warning',
                'message': f'Found: {", ".join(found)}'
            }]
        return [{
            'check': 'Homoglyphs',
            'status': 'Safe',
            'message': 'No suspicious characters'
        }]

    def check_virustotal(self, url):
        try:
            params = {'apikey': self.api_keys['virustotal'], 'resource': url}
            response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
            data = response.json()
            
            if data.get('positives', 0) > 0:
                return [{
                    'check': 'VirusTotal',
                    'status': 'Danger',
                    'message': f'{data["positives"]} security vendors flagged this URL'
                }]
            return [{
                'check': 'VirusTotal',
                'status': 'Safe',
                'message': 'No security vendors flagged this URL'
            }]
        except Exception as e:
            return [{
                'check': 'VirusTotal',
                'status': 'Error',
                'message': str(e)
            }]

    def display_results(self, results):
        print("\n" + Fore.YELLOW + "Scan Results:" + Style.RESET_ALL)
        print("-------------------")
        
        for result in results:
            color = Fore.WHITE
            if result['status'] == 'Danger':
                color = Fore.RED
            elif result['status'] == 'Warning':
                color = Fore.YELLOW
            elif result['status'] == 'Safe':
                color = Fore.GREEN
                
            print(f"{color}[{result['status']}] {result['check']}: {result['message']}")
        
        warnings = sum(1 for res in results if res['status'] in ['Warning', 'Danger'])
        print("\n" + Fore.CYAN + "Final Assessment:" + Style.RESET_ALL)
        if warnings == 0:
            print(Fore.GREEN + "No phishing indicators detected (Still be cautious!)")
        else:
            print(Fore.RED + f"{warnings} warnings detected - Possible phishing attempt!")

def main():
    parser = argparse.ArgumentParser(description='Phishing Link Scanner')
    parser.add_argument('url', nargs='?', help='URL to scan')
    parser.add_argument('--virustotal', help='VirusTotal API key')
    args = parser.parse_args()

    scanner = TerminalPhishingScanner(api_keys={
        'virustotal': args.virustotal
    })

    scanner.print_banner()
    
    if args.url:
        url = args.url
    else:
        url = input(Fore.BLUE + "Enter URL to scan: " + Style.RESET_ALL)
    
    scanner.run_scan(url)

if __name__ == "__main__":
    main()