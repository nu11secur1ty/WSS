"""Support for discovering Wordpress plugins."""
from os.path import exists, join, realpath
from json import loads
from re import I, findall, search
import webbrowser

from lib.request import *


class wpplugins(Request):
	def __init__(self, url, data, kwargs):
		self.url = url
		self.data = data
		self.kwargs = kwargs
		self.files = {}

		root = realpath(__file__).split('modules')[0]
		files_path = join(root, 'db', 'files.json')

		if exists(files_path):
			with open(files_path, 'r') as fl:
				self.files = loads(fl.read())

		Request.__init__(self, kwargs)

	def changelog(self, plugin):
		if self.kwargs['verbose'] is True:
			info('Checking plugins changelog...')
		for file in self.files.get('changelogs', []):
			url = Path(self.url, '/wp-content/plugins/'.format(plugin, file))
			resp = self.send(url=url, method="GET")
			if resp.status_code == 200 and resp.content != ("" or None):
				if resp.url == url:
					more('Changelog: %s' % (resp.url))
					break

	def fpd(self, plugin):
		if self.kwargs['verbose'] is True:
			info('Checking plugins full path disclosure...')

		for file in self.files.get('fpd', []):
			url = Path(self.url, '/wp-content/plugins/'.format(plugin, file))
			resp = self.send(url=url, method="GET")
			if resp.status_code == 200 and resp.content != ("" or None):
				if resp.url == url:
					if search(decode('<b>Fatal error</b>:'), resp.content, I):
						path_d = findall(decode('\x3c\x62\x3e\x28\x2f\x5c\x53\x2a\x29\x3c\x2f\x62\x3e'), resp.content)[0]
						more('FPD (Full Path Disclosure): %s' % (path_d.decode('utf-8')))
						break

	def license(self, plugin):
		if self.kwargs['verbose'] is True:
			info('Checking plugins license...')

		for file in self.files.get('license', []):
			url = Path(self.url, '/wp-content/plugins/'.format(plugin, file))
			resp = self.send(url=url, method="GET")
			if resp.status_code == 200 and resp.content != ("" or None):
				if resp.url == url:
					more('License: %s' % (resp.url))
					break

	def listing(self, plugin):
		if self.kwargs['verbose'] is True:
			info('Checking plugins directory listing...')

		for dir_ in self.files.get('dirs', []):
			url = Path(self.url, '/wp-content/plugins/'.format(plugin, dir_))
			resp = self.send(url=url, method="GET")
			if resp.status_code == 200 and resp.content != ("" or None):
				if search(decode('<title>Index of'), resp.content, I):
					more('Listing: %s' % (resp.url))

	def readme(self, plugin):
		if self.kwargs['verbose'] is True:
			info('Checking plugins readme...')

		for file in self.files.get('readme', []):
			url = Path(self.url, '/wp-content/plugins/'.format(plugin, file))
			resp = self.send(url=url, method="GET")
			if resp.status_code == 200 and resp.content != ("" or None):
				if resp.url == url:
					more('Readme: %s' % (resp.url))
					break

	def run(self):
		info('Passive enumeration plugins...')
		plugins = self.s_plugins()
		if plugins != []:
			for plugin in plugins:
				plus('Name: %s' % (plugin.decode('utf-8')))
				self.changelog(plugin)
				self.fpd(plugin)
				self.license(plugin)
				self.readme(plugin)
				self.listing(plugin)
				self.dbwpscan(plugin)
		else:
			plus('Not found plugins with passive enumeration')

	def s_plugins(self):
		plugin = []
		resp = self.send(url=self.url, method="GET")
		plugins = findall(decode('/wp-content/plugins/(.+?)/'), resp.content)
		for pl in plugins:
			if pl not in plugin:
				plugin.append(pl)
		return plugin

	def dbwpscan(self, plugin):
		if self.kwargs['verbose'] is True:
			info('Checking plugin vulnerabilities...')
		plugin = plugin.decode('utf-8')
		
		# Fix 2025
		# url = "https://www.wpvulndb.com/api/v2/plugins/%s"%(plugin)
		url = "https://wpscan.com/plugins/".format(plugin)
		
		# Check for vulnerabilities in the WPScan database...
		target_plugin = input("Give the name of the plugin...\n")
		check_vuln_plugin = "https://wpscan.com/plugin/"+ target_plugin
		print("Check the plugins found in WPScan base...\n")
		webbrowser.open(check_vuln_plugin)
		
		resp = self.send(url=url,method="GET")
		# print(resp.content)
		print(resp.status_code)
		if resp.headers['Content-Type'] == 'application/json':
			json = loads(resp.content)
			if json[plugin]:
				if json[plugin]['vulnerabilities']:
					for x in range(len(json[plugin]['vulnerabilities'])):
						more('Title: \033[1;31m%s'%(json[plugin]['vulnerabilities'][x]['title']))
						if json[plugin]['vulnerabilities'][x]['references'] != {}:
							if json[plugin]['vulnerabilities'][x]['references']['url']:
								for y in range(len(json[plugin]['vulnerabilities'][x]['references']['url'])):
									more('Reference: %s'%(json[plugin]['vulnerabilities'][x]['references']['url'][y]))
						more('Fixed in: %s'%(json[plugin]['vulnerabilities'][x]['fixed_in']))
				else: more('Read Carefully in the WPScan database')
			else: more('Read Carefully in the WPScan database')
		else: more('Read Carefully in the WPScan database')
		normal('')
