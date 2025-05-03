import requests as req
import argparse
import json
from argparse import RawTextHelpFormatter


class dir:
    def __init__(self):
        parser = argparse.ArgumentParser(
            description='Get List of Available WP-Directory ',
            formatter_class=RawTextHelpFormatter)
        parser.add_argument('url',
                            type=str,
                            help='Example:http://target_url.com')
        args = parser.parse_args()
        self.url = args.url
        self.f = open("wordlist.json", "r")
        self.json_obj = json.load(self.f)
        f = open("result.txt", "w")
        f.write(f"Results of {self.url}\n\n")
        f.close()
        self.result = open("result.txt", "a")

    def rootScanner(self):
        print('\nscanning root directory ...\n')
        for i in self.json_obj['root']:
            route = self.url + "/" + i
            res = req.get(route)
            self.result.write(f"{route} - status_code : {res.status_code}\n")

    def adminScanner(self):
        print('\nscanning wp-admin directory ...\n')
        for i in self.json_obj['wp-admin/']:
            route = self.url + "/wp-admin/" + i
            res = req.get(route)
            self.result.write(f"{route} - status_code : {res.status_code}\n")

    def contentScanner(self):
        print('\nscanning wp-content directory ...\n')
        for i in self.json_obj['wp-content/']:
            route = self.url + "/wp-content/" + i
            res = req.get(route)
            self.result.write(f"{route} - status_code : {res.status_code}\n")

    def includesScanner(self):
        print('\nscanning wp-include directory ...\n')
        for i in self.json_obj['wp-include/']:
            route = self.url + "/wp-include/" + i
            res = req.get(route)
            self.result.write(f"{route} - status_code : {res.status_code}\n")

    def execute(self):
        self.rootScanner()
        self.adminScanner()
        self.contentScanner()
        self.includesScanner()
        self.result.close()


s = dir()
s.execute()
