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

<<<<<<< HEAD
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


=======
>>>>>>> 9b9d8d8eda1f8d24f5c09402d1b7a0d02e0e99f6
def route(path):
  print path
  def x(a):
    print a
  return x

<<<<<<< HEAD

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
=======
class GenericServer(object):
  def __init__(self, host, port, **options):
    print "__init__"
    self.host = host
    self.port = int(port)
    self.server = None
    self.options = options

  def run(self, wsgi_app):
    pass


class WSGIRefServer(GenericServer):

  def run(self, wsgi_app):
    import wsgiref.simple_server as ref_srv
    class FixedHandler(ref_srv.WSGIRequestHandler):
      def address_string(self):  # Prevent reverse DNS lookups please.
        return self.client_address[0]

      def x_log_request(*args, **kw):
        if not self.quiet:
          return WSGIRequestHandler.log_request(*args, **kw)

    srv_class = ref_srv.WSGIServer
    hnd_class = FixedHandler
    self.server = ref_srv.make_server(self.host, self.port, wsgi_app, srv_class, hnd_class)
    try:
      self.server.serve_forever()
    except KeyboardInterrupt:
      self.server.server_close()


def wsgi_handler(environ, start_response):
  print "WSGI handler ..."
  status = '200 OK'
  headers = []
  exc_info = None
  writer = start_response(status, headers, exc_info)
  writer('test1')
  print writer
  return 'test2'


application = wsgi_handler
>>>>>>> 9b9d8d8eda1f8d24f5c09402d1b7a0d02e0e99f6


def run(host='0.0.0.0', port=12345, server_class=None, **opts):
  if server_class is None:
    server_class = WSGIRefServer
  print "Run"
  handle = server_class(host, port, **opts)
  handle.run(wsgi_handler)



if __name__ == '__main__':
  run()

# end 








