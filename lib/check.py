#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# WSS - Wordpress Security Scanner
# nu11secur1ty

from urllib.parse import urlparse

from lib.printer import *
import urllib3
urllib3.disable_warnings()

def Data(url,data):
	""" Check url and data path """
	if url.endswith('/') and data.startswith('/'):
		return url[:-1] + "?" + data[1:]
	if not url.endswith('/') and data.startswith('/'):
		return url + "?" + data[1:]
	if url.endswith('/') and not data.startswith('/'):
		return url[:-1] + "?" + data
	else: return url + "?" + data

def Path(url,path):
	""" Check path """
	if url.endswith('/') and path.startswith('/'):
		return url[:-1] + path
	if not url.endswith('/') and not path.startswith('/'):
		return url + "/" + path
	else: return url+path

def urlCheck(url):
	o = urlparse(url)
	if o.scheme not in ['http','https','']:
		exit(warn('Scheme %s not supported'%o.scheme))
	if o.scheme == '':
		return 'http://'+url
	return url
