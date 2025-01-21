#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# WSS - Wordpress Security Scanner
# nu11secur1ty

def readfile(path):
	return [lines.strip() for lines in open(path,'rb')]
