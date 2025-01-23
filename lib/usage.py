#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# WSS - Wordpress Security Scanner
# by nu11secur1ty

import sys
from time import strftime
import urllib3
urllib3.disable_warnings()

from lib.printer import *


def ptime(url):
	banner()
	plus('Target: %s'%url)
	plus('Starting: %s'%(strftime('%H:%M:%S')))
	normal('')

def banner():
	print("\n")
	print("$$       $$   $$$$$$    $$$$$$  ") 
	print("$$   $   $$  $$    $$  $$    $$ ")
	print("$$  $$$  $$  $$        $$       ")
	print("$$ $$ $$ $$   $$$$$$    $$$$$$  ")
	print("$$$$   $$$$        $$        $$ ")
	print("$$$     $$$  $$    $$  $$    $$ ")
	print("$$       $$   $$$$$$    $$$$$$  ")
	print("v0.4.0\n")
	print("WSS - Wordpress Security Scanner")
	print("by nu11secur1ty")
	print("\n")
	
def usage(e=False):
	banner()
	print("Usage: %s [options]\n"%(sys.argv[0]))
	print("\t-u --url\tTarget URL (e.g: http://site.com)")
	print("\t-b --brute\tBruteforce login via xmlrpc")
	print("\t-U --user\tSet username for bruteforce, default \"admin\"")
	print("\t-s --scan\tChecking wordpress plugin code")
	print("\t-p --proxy\tUse a proxy, (host:port)")
	print("\t-c --cookie\tSet HTTP Cookie header value")
	print("\t-a --agent\tSet HTTP User-agent header value")
	print("\t-r --ragent\tUse random User-agent header value")
	print("\t-R --redirect\tSet redirect target URL False")
	print("\t-t --timeout\tSeconds to wait before timeout connection")
	print("\t-w --wordlist\tSet wordlist, default \"db/wordlist.txt\"")
	print("\t-v --verbose\tPrint more informations")
	print("\t-h --help\tShow this help and exit\n")
	print("Example:")
	print("\t %s --url http://site.com/"%(sys.argv[0]))
	print("\t %s --url http://site.com --brute --user test"%(sys.argv[0]))
	print("\t %s --url http://site.com/ --brute --user admin --wordlist wordlist.txt\n"%(sys.argv[0]))
	if e: exit()
