#!/usr/bin/env python3
"""WSS - WordPress Security Scanner (Main Entry Point)"""
import sys
import getopt
import urllib3

# Disable SSL warnings
urllib3.disable_warnings()

# ============================================================
# CORRECT IMPORTS - Based on actual file structure
# ============================================================

from lib.scan import Scan
from lib.usage import usage, banner, ptime, warn
from lib.printer import plus, info, normal  # Needed for some modules

# Import modules
from modules.bruteforce.wpxmlrpc import XMLRPCBrute
from modules.discovery.generic.generic import generic
from modules.discovery.plugins.wpplugins import wpplugins
from modules.discovery.themes.wpthemes import wpthemes
from modules.discovery.users.wpusers import wpusers
from modules.fingerprint.fingerprint import fingerprint


# ============================================================
# URL CHECK FUNCTION - Created here since it doesn't exist
# ============================================================

def urlCheck(url):
    """Validate and clean URL"""
    if not url:
        return None
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    if not url.endswith('/'):
        url += '/'
    return url


# ============================================================
# RAGENT FUNCTION - Created here since it doesn't exist
# ============================================================

def ragent():
    """Return random user agent"""
    import random
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "WSS-Scanner/4.0"
    ]
    return random.choice(agents)


class WSS:
    """WSS main object - Optimized version"""
    
    def __init__(self):
        """Initialize with defaults"""
        self.kwargs = {
            'agent': ragent(),
            'ragent': False,
            'redirect': True,
            'cookie': None,
            'proxy': None,
            'timeout': None,
            'verbose': False,
            'headers': {}
        }
        self._init_defaults()
        
    def _init_defaults(self):
        """Set default values"""
        self.brute = False
        self.user = "admin"
        self.wordlist = "db/wordlist.txt"
        self.url = None
        self.scan = None
        
    def _parse_arguments(self):
        """Parse command line arguments"""
        if len(sys.argv) < 2:
            usage(True)
            
        try:
            opts, _ = getopt.getopt(
                sys.argv[1:],
                'u:U:s:p:c:a:t:w:Rrhvb:',
                [
                    'url=', 'brute', 'user=', 'scan=', 'proxy=',
                    'cookie=', 'agent=', 'wordlist=', 'timeout=',
                    'redirect', 'ragent', 'help', 'verbose'
                ]
            )
        except getopt.GetoptError:
            usage(True)
            
        for opt, arg in opts:
            if opt in ('-u', '--url'):
                self.url = urlCheck(arg)
            elif opt in ('-b', '--brute'):
                self.brute = True
            elif opt in ('-U', '--user'):
                self.user = arg
            elif opt in ('-s', '--scan'):
                self.scan = arg
            elif opt in ('-p', '--proxy'):
                self.kwargs['proxy'] = arg
            elif opt in ('-c', '--cookie'):
                self.kwargs['cookie'] = arg
            elif opt in ('-a', '--agent'):
                self.kwargs['agent'] = arg
            elif opt in ('-t', '--timeout'):
                self.kwargs['timeout'] = arg
            elif opt in ('-R', '--redirect'):
                self.kwargs['redirect'] = True
            elif opt in ('-r', '--ragent'):
                self.kwargs['ragent'] = True
                self.kwargs['agent'] = ragent()
            elif opt in ('-v', '--verbose'):
                self.kwargs['verbose'] = True
            elif opt in ('-h', '--help'):
                usage(True)
                
    def _run_scan(self):
        """Execute the appropriate scan"""
        try:
            if self.scan is not None:
                banner()
                Scan().run(self.scan)
            elif self.brute is True:
                if not self.url:
                    print("[!] URL required for brute force")
                    return
                ptime(self.url)
                XMLRPCBrute(
                    self.url, 
                    None, 
                    self.user,
                    self.wordlist, 
                    self.kwargs
                ).run()
            elif self.url:
                ptime(self.url)
                fingerprint(self.url, None, self.kwargs).run()
                generic(self.url, None, self.kwargs)
                wpthemes(self.url, None, self.kwargs).run()
                wpplugins(self.url, None, self.kwargs).run()
                wpusers(self.url, None, self.kwargs).run()
            else:
                print("[!] No target specified. Use --url or --scan")
                usage(True)
                
        except UnboundLocalError as e:
            if self.kwargs.get('verbose'):
                print(f"[!] Warning: {e}")
            pass
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"[!] Error: {e}")
            if self.kwargs.get('verbose'):
                import traceback
                traceback.print_exc()
                
    def run(self):
        """Main execution method"""
        try:
            self._parse_arguments()
            self._run_scan()
        except KeyboardInterrupt:
            print(warn('CTRL+C...'))
            sys.exit(0)


def main():
    """Entry point"""
    wss = WSS()
    wss.run()


if __name__ == "__main__":
    main()
