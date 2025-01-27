"""Support for discovering Wordpress files."""
from os.path import realpath
import urllib3
urllib3.disable_warnings()

from lib.readfile import *
from lib.request import *


class wpfile(Request):
	def __init__(self,url,data,kwargs):
		self.url = url 
		self.data = data
		self.kwargs = kwargs
		Request.__init__(self,kwargs)

	def run(self):
		if self.kwargs['verbose'] is True:
			info('Checking common files...')
		path  = realpath(__file__).split('modules')[0]
		path += "db/commonfile.wss"
		for file in readfile(path):
			url = Path(self.url,file.decode('utf-8'))
			resp = self.send(url=url,method="GET")
			if resp.status_code == 200 and resp.content != ("" or None):
				if resp.url == url:
					plus('%s file was found at: %s'%(file.decode('utf-8'),resp.url))
			else:
				print("The target is not responding or this file path in not exist...\n")
