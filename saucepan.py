# !/usr/bin/env python
# -*- coding: utf-8 -*-
#
#

import httplib
from collections import OrderedDict
from abc import abstractmethod

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

HTTP_CODE_RANGES = {1: 'Continue', 2: 'Success', 3: 'Redirect', 4: 'Request Error', 5: 'Server Error'}


def get_default_http_message(code):
  c = int(code) / 100
  return HTTP_CODE_RANGES.get(c, None)


def http_status(code, message=None):
  code = int(code)
  if message is None:
    message = HTTP_CODES.get(code, None)
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
    print "Starting WSGIRef simple server on {0}:{1}".format(host, port)
    self.server = ref_srv.make_server(host, port, wsgi_app, srv_class, hnd_class)
    try:
      self.server.serve_forever()
    except KeyboardInterrupt:
      self.server.server_close()


class LastUpdatedOrderedDict(OrderedDict):
  def __setitem__(self, key, value, dict_setitem=dict.__setitem__):
    if key in self:
      del self[key]
    OrderedDict.__setitem__(self, key, value, dict_setitem=dict_setitem)


class CaseInsensitiveHttpEnv(object):
  _extra_keys = ('CONTENT_TYPE', 'CONTENT_LENGTH')
  _env = None

  def __init__(self, env):
    self._env = env
    for k,v in env.iteritems():
      print k,v

  def __getitem__(self, item):
    return self.get(item, None)

  def get(self, item, default=None, require=False):
    item = str(item)
    item = item.upper()
    if item.startswith("HTTP_"):
      pass
    elif item == 'METHOD':
      item = 'REQUEST_METHOD'
    elif item == 'PROTOCOL':
      item = 'SERVER_PROTOCOL'
    else:
      item = "HTTP_" + item
    print "GET KEY ", item
    return self._env[item]

  def has(self, key):
    print "HAS ", key
    return self.get(key) is not None

  def check(self, key, val):
    cur_val = self.get(key, default=None)
    print "COMPARE ", key, val, cur_val
    if cur_val is None:
      return False
    if isinstance(val, list):
      if cur_val in val:
        return True
    return cur_val == val


class HttpMessage(object):
  body = ''


class HttpRequest(HttpMessage):
  verb = None
  version = None
  _http_proto = None
  _http_version = None
  headers = None

  def __init__(self, env):
    self.headers = CaseInsensitiveHttpEnv(env)
    self.verb = env.get('REQUEST_METHOD')
    self.version = env.get('SERVER_PROTOCOL')
    self._http_version, self._http_version = self.version.split('/')

  def uri(self, host=False):
    pass


CONTENT_LENGTH_HEADER = 'Content-Length'


class HttpResponse(HttpMessage):
  status_code = 200
  status_message = None
  headers = LastUpdatedOrderedDict()
  fix_content_length = True

  def __init__(self, version='HTTP/1.1'):
    pass

  def get_status(self):
    return http_status(self.status_code, self.status_message)

  def get_headers(self):  # return Camel-Case headers + values as list[]
    resp = []
    for k, v in self.headers.iteritems():
      resp.append((k.title(), str(v)))
    return resp

  def finish(self):  # calculate content-length header if not set
    if self.fix_content_length:
      s = len(self.body)
      self.headers[CONTENT_LENGTH_HEADER] = str(s)


class TheContext(object):
  def __init__(self, env):
    self.request = HttpRequest(env)
    self.response = HttpResponse(version=self.request.version)
    self.env = env


class AbstractRouter(object):
  _routes = []
  default = None

  def __init__(self):
    self.setup()

  @abstractmethod
  def setup(self):
    pass

  def _pre_process(self, kw):
    return kw

  def _default_route(self, ctx, **kw):
    if callable(self.default):
      self.default(ctx, **kw)

  def add_entry(self, testable, **kw):
    kw['testable'] = testable
    self._routes.append(self._pre_process(**kw))
    pass

  @abstractmethod
  def try_route(self, ctx, **route_args):
    pass

  def select_route(self, ctx):
    for rt in self._routes:
      if self.try_route(ctx, **rt):
        return ctx
    self._default_route(ctx)
    return ctx


ROUTE_CHECK_UNDEF = None
ROUTE_CHECK_STR = 1
ROUTE_CHECK_SIMPLE = 2
ROUTE_CHECK_REGEX = 3
ROUTE_CHECK_CALL = 4
ROUTE_GENERATOR = 5

DEFAULT_ROUTE_TYPE = ROUTE_CHECK_SIMPLE


def method(m):
  return [m]

METHOD_GET = ['GET']
METHOD_POST = ['POST']


class DefaultRouter(AbstractRouter):
  type_mapping = {}

  def setup(self):
    self.type_mapping[ROUTE_CHECK_STR] = self._test_str


  def _test_str(self, ctx, route):
    pass

  def _pre_process(self, **kw):
    testable = kw.get('testable')
    target = kw.get('target', None)
    route_type = kw.get('route_type', ROUTE_CHECK_UNDEF)
    if 'headers' not in kw:
      kw['headers'] = []
    else:
      if not isinstance(kw['headers'], list):
        kw['headers'] = []

    for key in kw:
      if key.startswith("check_"):
        item = key.split("_", 1)[1]
        kw['headers'].append((item, kw[key]))

    if route_type != ROUTE_CHECK_UNDEF:
      print "* Route type autodetect ..."
      print "  -> testable: ", `testable`, type(testable)
      if isinstance(testable, basestring):
        print "STRING !"
      if callable(testable):
        print "Testable is callable -> func test ?"
        if target is None:
          route_type = ROUTE_GENERATOR
        else:
          route_type = ROUTE_CHECK_CALL
      kw['route_type'] = route_type



    return kw


  def _test_generator(self, ctx, route):
    pass

  def try_route(self, ctx, _call=None, headers=None, **args):
    if headers and len(headers) > 0:
      for key, val in headers:
        if not ctx.request.headers.check(key, val):
          print "Did not get ", key, "", val
          return False
    _callable


  def try_route2(self, ctx, testable, route_type=ROUTE_CHECK_UNDEF, headers=None, **route_args):
    print "TEST", testable
    if route_type == ROUTE_CHECK_UNDEF:
      pass
      # raise Exception("invalid route type !")
    print route_type, ROUTE_GENERATOR
    ret_val = ''
    request_uri = ""

    if headers and len(headers) > 0:
      for key, val in headers:
        if not ctx.request.headers.check(key, val):
          print "Did not get ", key, "", val
          return False




    if route_type == ROUTE_GENERATOR:
      print "OMG YES YES YES "
      target = testable(ctx)
      if target is None:
        return False
      ret_val = target(ctx)
    elif route_type == ROUTE_CHECK_STR:
      return False
    else:
      return False

    if ret_val is not None:
      ctx.response.body = str(ret_val)
    return True


DEFAULT_HEADERS = {
  'Content-type': 'text/html',
  'Server': 'Saucepan (%s)' % __version__,
}


class CookingPot(object):
  _write_using_writer = False
  router = DefaultRouter()

  def __init__(self, router_class=None):
    if router_class:
      self.router = router_class()
    self.router.default = self._default_route

  def _default_route(self, ctx):
    ctx.response.status_code = 404
    return "Nope!"

  def route(self, testable, **kw):
    def _wrapper(f):
      print " ** wrapped : ", f, " ** "
      self.add_route(testable, target=f, **kw)

    return _wrapper

  def add_route(self, testable, target=None, **kw):
    print "Add router [%s] -> [%s] (%s)" % (testable, target, kw)
    self.router.add_entry(testable, target=target, **kw)

  def wsgi_handler(self, environ, start_response):
    exc_info = None
    try:
      print " ----> "
      ctx = TheContext(environ)
      for k, v in DEFAULT_HEADERS.iteritems():
        ctx.response.headers[k] = v
      self.router.select_route(ctx)
      ctx.response.finish()
      body = ctx.response.body
      headers = ctx.response.get_headers()
      status = ctx.response.get_status()
      print " <---- "
    except Exception as ex:
      import traceback
      import sys

      info = sys.exc_info()
      traceback.print_exception(*info)
      status = http_status(500)
      headers = []
      body = "html ok"
    print "Will answer", status, headers
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

# expose some globals, be bottle-like compatible ;-)
route = pan.route


def _wsgi_handler(environ, start_response):
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
