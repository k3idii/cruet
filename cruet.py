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

DEFAULT_LISTEN_HOST = '0.0.0.0'
DEFAULT_LISTEN_PORT = 8008

class WSGIApp(object:
  auto_handle = False

  def __init_(self, env, start_response):
    self.env = env
    self.start_response = start_response
    if self.auto_handle:
      self.handle()

  def handle(self):
    print "Handle !"


def route(path):
  print path
  def x(a):
    print a
  return x


class StandaloneServer(Object):

  srv = None

  def __init__(self, options, app):
    self.options = options
    self.app = app

  def run(self):
    pass


class WSGIRefServer(StandaloneServer):
  def run(self):
    import wsgiref.simple_server
    host = self.options.get('host', DEFAULT_LISTEN_HOST)
    port = self.options.get('port', DEFAUTT_LISTEN_PORT)
    srv_class = wsgiref.simple_server.WSGIServer
    hdn_class = wsgiref.simple_server.WSGIRequestHandler
    self.srv = wsgiref.simple_server.make_server(host, port, self.app, srv_class, hdn_class)
    try:
      self.srv.serve_forever()
    except KeyboardInterrupt:
      self.srv.server_close()
      raise



def standalone(): # parse commandline args, run()
  pass

def run(host='0.0.0.0', port=12345):
  print "Run"

def wsgi():
  pass