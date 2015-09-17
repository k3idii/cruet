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


def run(host='0.0.0.0', port=12345, server_class=None, **opts):
  if server_class is None:
    server_class = WSGIRefServer
  print "Run"
  handle = server_class(host, port, **opts)
  handle.run(wsgi_handler)



if __name__ == '__main__':
  run()

# end 








