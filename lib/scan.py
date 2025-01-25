#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# WSS - Wordpress Security Scanner
# nu11secur1ty

import fnmatch
import glob
import json
import os
import re
import sys
import time
import urllib3
urllib3.disable_warnings()

from humanfriendly.tables import format_pretty_table

from lib.printer import *
from lib.readfile import *


class Scan:
	"""
	Scanning PHP Code
	https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet
	"""
	table = ['Line','Possibile Vuln.','String']
	vuln = {
			'csrf' : 'Cross-Site Request Forgery',
			'xss'  : 'Cross-Site Scripting',
			'sql'  : 'SQL Injection',
			'op'   : 'Open Redirect',
			'pce'  : 'PHP Code Execution',
			'com'  : 'Command Execution',
			'auth' : 'Authorization Hole',
			'php'  : 'PHP Object Injection',
			'fi'   : 'File Inclusion',
			'fd'   : 'File Download',
			}
	def check(self,filename):
		if not filename.endswith('.php'):
			exit(warn('Not found file with php extension'))
		else:
			return filename

	def recursive(self,rootdir,pattern):
		matchs = []
		for root,dirnames,filenames in os.walk(rootdir):
			for filename in fnmatch.filter(filenames,pattern):
				matchs.append(os.path.join(root,filename))
		return matchs

	def run(self,source):
		plus('Checking PHP code...')
		if os.path.isdir(source):
			plus('Scanning directory...')
			files = self.recursive(source,'*.php')
			for file in files:
				try:
					with open(file, 'tr') as check_file:  # Try open file in text mode
						check_file.read()
						info('Scanning %s file'%file)
						self.testFile(file)
				except:  # If check_file.read fails, then file is non-text (possibly binary)
					warn("Skipping %s"%file)
					pass

		else:
			plus('Scanning file...')
			file = self.check(source)
			self.testFile(file)

	def testFile(self,file):
		res = []
		code = readfile(file)
		res += self.csrf(code)
		res += self.ope(code)
		res += self.pce(code)
		res += self.com(code)
		res += self.auth(code)
		res += self.php(code)
		res += self.fin(code)
		res += self.fid(code)
		res += self.sql(code)
		res += self.xss(code)
		if res != []:
			print(format_pretty_table(res,self.table))
		else: plus('Not found vulnerabilities')

	def csrf(self,code):
		# check cross-site request forgery
		vuln = []
		blacklist = [
		             '\x5e\x77\x70\x5f\x6e\x6f\x6e\x63\x65\x5f\x66\x69\x65\x6c\x64\x5c\x28\x5c\x53\x2a\x5c\x29','\x5e\x77\x70\x5f\x6e\x6f\x6e\x63\x65\x5f\x75\x72\x6c\x5c\x28\x5c\x53\x2a\x5c\x29',
		             '\x5e\x77\x70\x5f\x76\x65\x72\x69\x66\x79\x5f\x6e\x6f\x6e\x63\x65\x5c\x28\x5c\x53\x2a\x5c\x29','\x5e\x63\x68\x65\x63\x6b\x5f\x61\x64\x6d\x69\x6e\x5f\x72\x65\x66\x65\x72\x65\x72\x5c\x28\x5c\x53\x2a\x5c\x29'
		             ]
		for b in blacklist:
			b = decode(b)
			for line,cd in enumerate(code):
				pattern = re.findall(b.decode("utf-8"),cd.decode("utf-8"),re.I)
				if pattern != []:
					vuln.append([line,self.vuln['csrf'],pattern[0]])
		return vuln
	
	def ope(self,code):
		# check open redirect
		vuln = []
		blacklist = [
					 '\x5e\x77\x70\x5f\x72\x65\x64\x69\x72\x65\x63\x74\x5c\x28\x5c\x53\x2a\x5c\x29'
					 ]
		for b in blacklist:
			b = decode(b)
			for line,cd in enumerate(code):
				pattern = re.findall(b.decode("utf-8"),cd.decode("utf-8"),re.I)
				if pattern != []:
					vuln.append([line,self.vuln['op'],pattern[0]])
		return vuln

	def pce(self,code):
		# check php code execution
		vuln = []
		blacklist = [
					  '\x5e\x65\x76\x61\x6c\x5c\x28\x5c\x53\x2a\x5c\x29', '\x5e\x61\x73\x73\x65\x72\x74\x5c\x28\x5c\x53\x2a\x5c\x29','\x5e\x70\x72\x65\x67\x5f\x72\x65\x70\x6c\x61\x63\x65\x5c\x28\x5c\x53\x2a\x5c\x29'
					  ]
		for b in blacklist:
			b = decode(b)
			for line,cd in enumerate(code):
				pattern = re.findall(b.decode("utf-8"),cd.decode("utf-8"),re.I)
				if pattern != []:
					vuln.append([line,self.vuln['pce'],pattern[0]])
		return vuln
	
	def com(self,code):
		# check command execution
		vuln = []
		blacklist = [
					 '\x5e\x73\x79\x73\x74\x65\x6d\x5c\x28\x5c\x53\x2a\x5c\x29', '\x5e\x65\x78\x65\x63\x5c\x28\x5c\x53\x2a\x5c\x29','\x5e\x70\x61\x73\x73\x74\x68\x72\x75\x5c\x28\x5c\x53\x2a\x5c\x29','\x5e\x73\x68\x65\x6c\x6c\x5f\x65\x78\x65\x63\x5c\x28\x5c\x53\x2a\x5c\x29'
					 ]
		for b in blacklist:
			b = decode(b)
			for line,cd in enumerate(code):
				pattern = re.findall(b.decode("utf-8"),cd.decode("utf-8"),re.I)
				if pattern != []:
					vuln.append([line,self.vuln['com'],pattern[0]])
		return vuln

	def auth(self,code):
		# check authorization hole
		vuln = []
		blacklist = [
					 '\x5e\x69\x73\x5f\x61\x64\x6d\x69\x6e\x5c\x28\x5c\x53\x2a\x5c\x29','\x5e\x69\x73\x5f\x75\x73\x65\x72\x5f\x61\x64\x6d\x69\x6e\x5c\x28\x5c\x53\x2a\x5c\x29'
					 ]
		for b in blacklist:
			b = decode(b)
			for line,cd in enumerate(code):
				pattern = re.findall(b.decode("utf-8"),cd.decode("utf-8"),re.I)
				if pattern != []:
					vuln.append([line,self.vuln['auth'],pattern[0]])
		return vuln

	def php(self,code):
		# check php object injection
		vuln = []
		blacklist = [
					 '\x5e\x75\x6e\x73\x65\x72\x69\x61\x6c\x69\x7a\x65\x5c\x28\x5c\x53\x2a\x5c\x29'
					 ]
		for b in blacklist:
			b = decode(b)
			for line,cd in enumerate(code):
				pattern = re.findall(b.decode("utf-8"),cd.decode("utf-8"),re.I)
				if pattern != []:
					vuln.append([line,self.vuln['php'],pattern[0]])
		return vuln

	def fin(self,code):
		# check file inclusion
		vuln = []
		blacklist = [
					 '\x5e\x69\x6e\x63\x6c\x75\x64\x65\x5c\x28\x5c\x53\x2a\x5c\x29','\x5e\x72\x65\x71\x75\x69\x72\x65\x5c\x28\x5c\x53\x2a\x5c\x29',
					 '\x5e\x69\x6e\x63\x6c\x75\x64\x65\x5f\x6f\x6e\x63\x65\x5c\x28\x5c\x53\x2a\x5c\x29','\x5e\x72\x65\x71\x75\x69\x72\x65\x5f\x6f\x6e\x63\x65\x5c\x28\x5c\x53\x2a\x5c\x29','\x5e\x66\x72\x65\x61\x64\x5c\x28\x5c\x53\x2a\x5c\x29'
					 ]
		for b in blacklist:
			b = decode(b)
			for line,cd in enumerate(code):
				pattern = re.findall(b.decode("utf-8"),cd.decode("utf-8"),re.I)
				if pattern != []:
					vuln.append([line,self.vuln['fi'],pattern[0]])
		return vuln

	def fid(self,code):
		# check file download
		vuln = []
		blacklist = [
					 '\x5e\x66\x69\x6c\x65\x5c\x28\x5c\x53\x2a\x5c\x29','\x5e\x72\x65\x61\x64\x66\x69\x6c\x65\x5c\x28\x5c\x53\x2a\x5c\x29','\x5e\x66\x69\x6c\x65\x5f\x67\x65\x74\x5f\x63\x6f\x6e\x74\x65\x6e\x74\x73\x5c\x28\x5c\x53\x2a\x5c\x29'
					 ]
		for b in blacklist:
			b = decode(b)
			for line,cd in enumerate(code):
				pattern = re.findall(b.decode("utf-8"),cd.decode("utf-8"),re.I)
				if pattern != []:
					vuln.append([line,self.vuln['fd'],pattern[0]])
		return vuln
	
	def sql(self,code):
		# check sql injection
		vuln = []
		blacklist = [
					 '\x3f\x5c\x24\x77\x70\x64\x62\x2d\x3e\x71\x75\x65\x72\x79\x5c\x28\x5c\x53\x2a\x5c\x29','\x5e\x5c\x24\x77\x70\x64\x62\x2d\x3e\x67\x65\x74\x5f\x76\x61\x72\x5c\x28\x5c\x53\x2a\x5c\x29','\x5e\x5c\x24\x77\x70\x64\x62\x2d\x3e\x67\x65\x74\x5f\x72\x6f\x77\x5c\x28\x5c\x53\x2a\x5c\x29','\x5e\x5c\x24\x77\x70\x64\x62\x2d\x3e\x67\x65\x74\x5f\x63\x6f\x6c\x5c\x28\x5c\x53\x2a\x5c\x29',
					 '\x3f\x5c\x24\x77\x70\x64\x62\x2d\x3e\x67\x65\x74\x5f\x72\x65\x73\x75\x6c\x74\x73\x5c\x28\x5c\x53\x2a\x5c\x29','\x5e\x5c\x24\x77\x70\x64\x62\x2d\x3e\x72\x65\x70\x6c\x61\x63\x65\x5c\x28\x5c\x53\x2a\x5c\x29','\x5e\x65\x73\x63\x5f\x73\x71\x6c\x5c\x28\x5c\x53\x2a\x5c\x29','\x5e\x65\x73\x63\x61\x70\x65\x5c\x28\x5c\x53\x2a\x5c\x29','\x5e\x65\x73\x63\x5f\x6c\x69\x6b\x65\x5c\x28\x5c\x53\x2a\x5c\x29',
					 '\x5e\x6c\x69\x6b\x65\x5f\x65\x73\x63\x61\x70\x65\x5c\x28\x5c\x53\x2a\x5c\x29'
					 ]
		for b in blacklist:
			b = decode(b)
			for line,cd in enumerate(code):
				pattern = re.findall(str(b),str(cd),re.I)
				if pattern != []:
					vuln.append([line,self.vuln['sql'],pattern[0]])
		return vuln

	def xss(self,code):
		# check cross-site scripting
		vuln = []
		blacklist = [
					 '\x5e\x5c\x24\x5f\x47\x45\x54\x5c\x5b\x5c\x53\x2a\x5c\x5d','\x5e\x5c\x24\x5f\x50\x4f\x53\x54\x5c\x5b\x5c\x53\x2a\x5c\x5d','\x5e\x5c\x24\x5f\x52\x45\x51\x55\x45\x53\x54\x5c\x5b\x5c\x53\x2a\x5c\x5d','\x5e\x5c\x24\x5f\x53\x45\x52\x56\x45\x52\x5c\x5b\x5c\x53\x2a\x5c\x5d','\x5e\x5c\x24\x5f\x43\x4f\x4f\x4b\x49\x45\x5c\x5b\x5c\x53\x2a\x5c\x5d',
					 '\x5e\x61\x64\x64\x5f\x71\x75\x65\x72\x79\x5f\x61\x72\x67\x5c\x28\x5c\x53\x2a\x5c\x29','\x5e\x72\x65\x6d\x6f\x76\x65\x5f\x71\x75\x65\x72\x79\x5f\x61\x72\x67\x5c\x28\x5c\x53\x2a\x5c\x29'
					 ]
		for b in blacklist:
			b = decode(b)
			for line,cd in enumerate(code):
				pattern = re.findall(b.decode("utf-8"),cd.decode("utf-8"),re.I)
				if pattern != []:
					vuln.append([line,self.vuln['xss'],pattern[0]])
		return vuln
