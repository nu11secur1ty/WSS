"""Support for fingerprinting CMS."""
from re import I, search

from lib.printer import *
import urllib3
urllib3.disable_warnings()


def wordpress(headers,content):
	_cms_ = False
	_cms_ |= search(decode('<meta name="generator" content="WordPress'),content) is not None
	_cms_ |= search(decode('<a href="http://www.wordpress.com">Powered by WordPress</a>'),content) is not None
	_cms_ |= search(decode('<link rel=\'https://api.w.org/\''),content) is not None
	# decode utf8
	_cms_ |= search(decode('\x5c\x5c\x3f\x5c\x2f\x77\x70\x2d\x63\x6f\x6e\x74\x65\x6e\x74\x5c\x5c\x3f\x5c\x2f\x70\x6c\x75\x67\x69\x6e\x73\x5c\x2f\x7c\x5c\x5c\x3f\x5c\x2f\x77\x70\x2d\x61\x64\x6d\x69\x6e\x5c\x5c\x3f\x5c\x2f\x61\x64\x6d\x69\x6e\x2d\x61\x6a\x61\x78\x2e\x70\x68\x70'),content) is not None
	if _cms_:
		return "wordpress"

def joomla(headers,content):
	_cms_  = False
	if 'Set-Cookie' in headers.keys():
		_cms_ |= search("mosvisitor=",headers["Set-Cookie"],I) is not None
	_cms_ |= search(decode("<meta name=\"Generator\" content=\"Joomla! - Copyright (C) 200[0-9] - 200[0-9] Open Source Matters. All rights reserved.\" />"),content) is not None
	# decode utf8
	_cms_ |= search(decode("\x3c\x6d\x65\x74\x61\x20\x6e\x61\x6d\x65\x3d\x5c\x22\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\x5c\x22\x20\x63\x6f\x6e\x74\x65\x6e\x74\x3d\x5c\x22\x4a\x6f\x6f\x6d\x6c\x61\x21\x20\x28\x5c\x64\x5c\x2e\x5c\x64\x29\x20\x2d\x20\x4f\x70\x65\x6e\x20\x53\x6f\x75\x72\x63\x65\x20\x43\x6f\x6e\x74\x65\x6e\x74\x20\x4d\x61\x6e\x61\x67\x65\x6d\x65\x6e\x74\x5c\x22\x20\x2f\x3e"),content) is not None
	_cms_ |= search(decode("Powered by <a href=\"http://www.joomla.org\">Joomla!</a>."),content) is not None
	if _cms_ :
		return "joomla"

def drupal(headers,content):
	_cms_ = False
	if 'Set-Cookie' in headers.keys():
		_cms_ |= search("SESS[a-z0-9]{32}=[a-z0-9]{32}",headers["Set-Cookie"],I) is not None
	if 'X-Drupal-Cache' in headers.keys(): _cms_ |= True
	_cms_ |= search(decode("<script type=\"text/javascript\" src=\"[^\"]*/misc/drupal.js[^\"]*\"></script>"),content) is not None
	_cms_ |= search(decode("<[^>]+alt=\"Powered by Drupal, an open source content management system\""),content) is not None
	_cms_ |= search(decode("@import \"[^\"]*/misc/drupal.css\""),content) is not None
	# decode utf8
	_cms_ |= search(decode("\x6a\x51\x75\x65\x72\x79\x2e\x65\x78\x74\x65\x6e\x64\x5c\x28\x64\x72\x75\x70\x61\x6c\x5c\x2e\x53\x2a"),content) is not None
	_cms_ |= search(decode("\x44\x72\x75\x70\x61\x6c\x2e\x65\x78\x74\x65\x6e\x64\x5c\x28\x5c\x53\x2a"),content) is not None
	if _cms_ :
		return "drupal"

def cms(headers,content):
	return (
			wordpress(headers,content),
			joomla(headers,content),
			drupal(headers,content)
			)
