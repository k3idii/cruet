# !/usr/bin/env python
# -*- coding: utf-8 -*-
#
#

import httplib

__author__ = 'KeiDii'
__version__ = '0.2'
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

def http_status(code, message=None):
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

  def _pre_process(self, kw):
    return kw

  def add_entry(self, testable, **kw):
    kw['testable'] = testable
    self._routes.append(self._pre_process(**kw))
    pass

  def test_route(self, env, route):
    return True

  def use_route(self, route):
    return None

  def select_route(self, env):
    for route in self._routes:
      if self.test_route(env, route):
        return self.use_route(route)
    return None


ROUTE_CHECK_UNDEF = None
ROUTE_CHECK_STRSTR = 1
ROUTE_CHECK_SIMPLE = 2
ROUTE_CHECK_REGEX = 3
ROUTE_CHECK_CALL = 4
ROUTE_GENERATOR = 5


def method(m):
  return [m]

METHOD_GET = ['GET']
METHOD_POST = ['POST']


class DefaultRouter(AbstractRouter):

  def _pre_process(self, handler=None, route_type=ROUTE_CHECK_UNDEF, **other):

    if route_type == ROUTE_CHECK_UNDEF:
      print "route type autodetect ..."
      print `handler`
      print type(handler)
      if callable(handler):
        print "Route is callable !"
        route_type = ROUTE_CHECK_CALL
      else:
        print type()


    print "Route type " , route_type

    return dict(handler=handler, route_type=route_type).update(other)

  def test_route(self, env, route):
    print route
    return False








class HttpMessage(object):
  _headers = []
  _body = ''


class HttpRequest(HttpMessage):
  pass

class HttpResponse(HttpMessage):
  pass



class CookingPot(object):

  _write_using_writer = False
  router = DefaultRouter()

  def __init__(self, router_class=None):
    if router_class:
      router = router_class()
    pass

  def route(self, testable, *a, **kw):
    def _wrapper(f):
      print " ** wrapped : ", f , " ** "
      self.add_route(testable, target=f, **kw)
    return _wrapper

  def add_route(self, testable, target=None, **kw):
    print "Add router [%s] -> [%s] (%s)" % (testable, target, kw)
    self.router.add_entry(testable, target=target, **kw)


  def handle_request(self):
    pass

  def wsgi_handler(self, environ, start_response):
    self.router.select_route(environ)
    status = http_status(200)
    headers = []
    exc_info = None
    body = "<html> it is"

    body_writer = start_response(status, headers, exc_info)

    if self._write_using_writer:
      if callable(body_writer):
        body_writer(body)
        return ''
      else:
        return body
    else:
      return body








pan = CookingPot()



# expose some globals, be bottle compatible ;-)
route = pan.route


def _wsgi_handler(environ, start_response):
  print "External WSGI handler ..."
  # forward request to global scope object
  return pan.wsgi_handler(environ, start_response)

def wsgi_interface():
  return _wsgi_handler

# expose WSGI handler
application = wsgi_interface()

def run(server_class=None, **opts):
  if server_class is None:
    server_class = WSGIRefServer
  handle = server_class(**opts)
  handle.run(_wsgi_handler)

if __name__ == '__main__':
  run()

# end
