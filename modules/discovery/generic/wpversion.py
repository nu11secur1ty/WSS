"""Support for discovering Wordpress versions."""
from json import loads
from re import findall
import urllib3
urllib3.disable_warnings()

from lib.request import *


class wpversion(Request):
	def __init__(self,url,data,kwargs):
		self.url = url 
		self.data = data
		self.kwargs = kwargs
		Request.__init__(self,kwargs)

	def run(self):
		if self.kwargs['verbose'] is True:
			info('Checking WordPress version...')
		try:
			url = Path(self.url,'/wp-links-opml.php')
			resp = self.send(url=url,method="GET")
			if resp.status_code == 200 and resp.content != ("" or None):
				version = findall(decode('\x5c\x53\x2b\x57\x6f\x72\x64\x50\x72\x65\x73\x73\x2f\x28\x5c\x64\x2b\x2e\x5c\x64\x2b\x5b\x2e\x5c\x64\x2b\x5d\x2a\x29'),resp.content)
				if version:
					plus('Running WordPress version: %s'%version[0].decode('utf-8'))
					self.dbwpscan(version)
		except Exception as e:
			pass
# No need :)
#			try:
#				url = Path(self.url,'feed')
#				resp = self.send(url=url,method="GET")
#				if resp.status_code == 200 and resp.content != ("" or None):
#					version = findall(decode('\S+?v=(\d+.\d+[.\d+]*)'),resp.content)
#					if version:
#						plus('Running WordPress version: %s'%version[0].decode('utf-8'))
#						self.dbwpscan(version)
#			except Exception as e:
#				try:
#					url = Path(self.url,'/feed/atom')
#					resp = self.send(url=url,method="GET")
#					if resp.status_code == 200 and resp.content != ("" or None):
#						version = findall(decode('<generator uri="http://wordpress.org/" version="(\d+\.\d+[\.\d+]*)"'),resp.content)
#						if version:
#							plus('Running WordPress version: %s'%version[0].decode('utf-8'))
#							self.dbwpscan(version)
#				except Exception as e:
#					try:
#						url = Path(self.url,'/readme.html')
#						resp = self.send(url=url,method="GET")
#						if resp.status_code == 200 and resp.content != ("" or None):
#							version = findall(decode('.*wordpress-logo.png" /></a>\n.*<br />.* (\d+\.\d+[\.\d+]*)\n</h1>'),resp.content)
#							if version:
#								plus('Running WordPress version: %s'%version[0].decode('utf-8'))
#								self.dbwpscan(version)
#					except Exception as e:
#						try:
#							url = Path(self.url,'')
#							resp = self.send(url=url,method="GET")
#							if resp.status_code == 200 and resp.content != ("" or None):
#								version = findall(decode('<meta name="generator" content="WordPress (\d+\.\d+[\.\d+]*)"'),resp.content)
#								if version:
#									plus('Running WordPress version: %s'%version[0].decode('utf-8'))
#									self.dbwpscan(version)
#						except Exception:
#							pass
	def dbwpscan(self,version):
		# For developement...
		# url = "https://www.wpvulndb.com/api/v2/wordpresses/%s"%self.version(version)
		# url = "https://wordpressversionchecker.com/%s"%self.version(version)
		version = version[0].decode('utf-8')
		resp = self.send(url=url,method="GET")
		json = loads(resp.content)
		if resp.headers['Content-Type'] == 'application/json':
			if json[version]:
				if json[version]['release_date']:
					more('Release date: %s'%(json[version]['release_date']))
					if json[version]['vulnerabilities']:
						for x in range(len(json[version]['vulnerabilities'])):
							more('Title: %s'%(json[version]['vulnerabilities'][x]['title']))
							if json[version]['vulnerabilities'][x]['references']['url']:
								for y in range(len(json[version]['vulnerabilities'][x]['references']['url'])):
									more('Reference: %s'%(json[version]['vulnerabilities'][x]['references']['url'][y]))
							more('Fixed in: %s'%(json[version]['vulnerabilities'][x]['fixed_in']))
					else: more('Not found vulnerabilities')
				else: more('Not found vulnerabilities')
			else: more('Not found vulnerabilities')
		else: more('Not found vulnerabilities')

	def version(self,version):
		vers = ""
		version = version[0].decode('utf-8')	
		for v in range(len(version.split('.'))):
			vers += version.split('.')[v]
		return vers
