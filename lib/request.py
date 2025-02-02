#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# WSS - Wordpress Security Scanner
# nu11secur1ty

import requests
import urllib3
urllib3.disable_warnings()

from lib.check import *
from lib.printer import *
from lib.ragent import *


class Request(object):
	def __init__(self,kwarg):
		self.kwarg = kwarg

	def send(self,url,method="GET",data=None,headers=None,cookie=None):
		if data is None: data = {}
		if headers is None: headers = {}
		headers = self.kwarg['headers']
		if cookie is not None: headers['Cookie'] = cookie
		if self.kwarg['cookie']: headers['Cookie'] = self.kwarg['cookie']
		headers['User-Agent'] = self.kwarg['agent']
		# set random user-agent if argv --ragent is true
		if self.kwarg['ragent'] is True:
			if self.kwarg['verbose'] is True:
				info('setting random user-agent...')
			self.kwarg['agent'] =  ragent()
		# make request session
		make_req = requests.Session()
		# disable request warnings
		req = requests.packages.urllib3.disable_warnings(
			urllib3.exceptions.InsecureRequestWarning
			)
		try:
			# get
			if method.lower() == "get":
				if data: url = "{}".format(Data(url,data))
				req = make_req.request(
					method = method.upper(),
					url = url,
					headers = headers,
					timeout = self.kwarg['timeout'],
					allow_redirects = self.kwarg['redirect'],
					verify = False,
					proxies = {
							'http':self.kwarg['proxy'],
							'https':self.kwarg['proxy']
							})
			# post
			elif method.lower() == "post":
				req = make_req.request(
					method = method.upper(),
					url = url,
					data = data,
					headers = headers,
					timeout = self.kwarg['timeout'],
					allow_redirects = self.kwarg['redirect'],
					verify = False,
					proxies = {
						    'http':self.kwarg['proxy'],
						    'https':self.kwarg['proxy']
						    })
		except requests.exceptions.ConnectionError:
			exit(warn('WARNING: The connection is lost! It depends on the defense of the target!'))
		# return req attr
		return req
