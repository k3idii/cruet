# !/usr/bin/env python
# -*- coding: utf-8 -*-
#
#

import httplib

__author__ = 'KeiDii'
__version__ = '0.1'
__license__ = 'MIT'


DEFAULT_LISTEN_HOST = '0.0.0.0'
DEFAULT_LISTEN_PORT = 8008


HTTP_CODES = httplib.responses.copy()
HTTP_CODES[418] = "I'm a teapot"  # RFC 2324
HTTP_CODES[428] = "Precondition Required"
HTTP_CODES[429] = "Too Many Requests"
HTTP_CODES[431] = "Request Header Fields Too Large"

HTTP_CODE_RANGES = {1 : 'Continue', 2 : 'Success', 3 : 'Redirect', 4 : 'Request Error',  5 : 'Server Error'}

def get_default_http_message(code):
  c = int(code)/100
  return HTTP_CODE_RANGES.get(c,None)

def http_statu(code, message=None):
  code = int(code)
  if message is None:
    message = HTTP_CODES.get(code,None)
    if message is None:
      message = get_default_http_message(code)
      if message is None:
        message = 'WTF'
  return "{0} {1}".format(code, message)




class GenericServer(object):
  """ Generic, bottle-compatible build-in server """
  def __init__(self, **options):
    self.server = None
    self.options = options

  def run(self, wsgi_app):
    """
    Should Run forever
    :param wsgi_app: wsgi application
    :return:
    """
    pass


class WSGIRefServer(GenericServer):
  """ WSGIRef-based server
  """
  def run(self, wsgi_app):

    host = self.options.get('host', DEFAULT_LISTEN_HOST)
    port = int(self.options.get('port', DEFAULT_LISTEN_PORT))

    import wsgiref.simple_server as ref_srv

    class FixedHandler(ref_srv.WSGIRequestHandler):
      def address_string(self):  # Prevent reverse DNS lookups please.
        return self.client_address[0]

      def log_request(*args, **kw):
        pass

    srv_class = ref_srv.WSGIServer
    hnd_class = FixedHandler
    print "Starting WSGIRef simple server on {0}:{1}".format(host,port)
    self.server = ref_srv.make_server(host, port, wsgi_app, srv_class, hnd_class)
    try:
      self.server.serve_forever()
    except KeyboardInterrupt:
      self.server.server_close()




class CIDict(dict): # Case Insensitive Dict
  pass


class AbstractRouter(object):
  _routes = []
  def __init__(self):
    pass

  def add_route(self, *a, **kw):
    pass

  def test_route(self, env, route):
    return Fase

  def use_route(self, route):
    return None

  def select_route(self, env):
    for route in self._routes:
      if self.test_route(env, route):
        return self.use_route(route)
    return None

class DefaultRouter(object):

  def add_route(self, path=None, **kw):
    pass

class HttpMessage(object):
  _headers = []
  _body = ''


class HttpRequest(HttpMessage):
  pass

class HttpResponse(HttpMessage):
  pass


class Cruet(object):

  _write_using_writer = False
  _router = DefaultRouter()

  def __init__(self):
    pass

  def route(self, *a, **kw):
    def wrapper(f):
      print "Wrapped :", f

    print a, kw
    return wrapper

  def add_route(self, *a, **kw):
    pass


  def handle_request(self):
    pass

  def wsgi_handler(self, environ, start_response):

    status = '200 OK'
    headers = []
    exc_info = None
    body_writer = start_response(status, headers, exc_info)

    body = "<html> it is"

    if self._write_using_writer:
      body_writer(body)
      return ''
    else:
      return body



def wsgi_handler(environ, start_response):
  print "External WSGI handler ..."
  # forward request to global scope Cruet instance
  return cr.wsgi_handler(environ, start_response)







cr = Cruet()







# expose functions :
route = cr.route
add_route = cr.add_route

# expose WSGI handler
application = wsgi_handler





def run(server_class=None, **opts):
  if server_class is None:
    server_class = WSGIRefServer
  handle = server_class(**opts)
  handle.run(wsgi_handler)

if __name__ == '__main__':
  run()

# end
