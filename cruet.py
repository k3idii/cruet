# !/usr/bin/env python
# -*- coding: utf-8 -*-
#
#

__author__ = 'KeiDii'
__version__ = '0.1'
__license__ = 'MIT'


DEFAULT_LISTEN_HOST = '0.0.0.0'
DEFAULT_LISTEN_PORT = 8008


class GenericServer(object):
  def __init__(self, **options):
    print "__init__"
    self.server = None
    self.options = options

  def run(self, wsgi_app):
    pass


class WSGIRefServer(GenericServer):
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

class RequestRouter(object):
  pass


class Cruet(object):

  _write_using_writer = False

  def __init__(self):
    pass

  def route(self, *a, **kw):
    def wrapper(f):
      print "Wrapped :", f

    print a, kw
    return wrapper

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


def run(server_class=None, **opts):
  if server_class is None:
    server_class = WSGIRefServer
  handle = server_class(**opts)
  handle.run(wsgi_handler)

def wsgi_handler(environ, start_response):
  print "External WSGI handler ..."
  # forward request to global scope Cruet instance
  return cr.wsgi_handler(environ, start_response)

cr = Cruet()

# expose functions :
route = cr.route

# expose WSGI handler
application = wsgi_handler


if __name__ == '__main__':
  run()

# end
