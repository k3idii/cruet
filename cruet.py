#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#

__author__ = 'KeiDii'
__version__ = '0.1'
__license__ = 'MIT'

#
#
#



def route(path):
  print path
  def x(a):
    print a
  return x

def standalone(): # parse commandline args, run()
  pass

def run(host='0.0.0.0', port=12345):
  print "Run"

def wsgi():
  pass