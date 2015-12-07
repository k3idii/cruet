# !/usr/bin/env python
# -*- coding: utf-8 -*-
#

import httplib
from collections import OrderedDict
from abc import abstractmethod
import re
import time
import logging
import json
import os
import os.path
import io

# is this present on al os ?
import mimetypes

__author__ = 'KeiDii'
__version__ = '0.41'
__license__ = 'MIT'

DEFAULT_LISTEN_HOST = '0.0.0.0'
DEFAULT_LISTEN_PORT = 8008

MAX_CONTENT_SIZE = 1 * 1024 * 1024 # 1 MB

# const strings :

# common header names :
HEADER_LOCATION = "Location"
HEADER_CONTENT_LENGTH = 'Content-Length'
HEADER_CONTENT_TYPE = 'Content-type'
HEADER_CONTENT_ENCODING = 'Content-encoding'
HEADER_CONTENT_DISPOSITION = 'Content-disposition'
HEADER_CONTENT_RANGE = 'Content-Range'
HEADER_LAST_MODIFIED = 'Last-modified'
HEADER_SERVER = 'Server'
HEADER_RANGE = 'Range'

SAVE_AS_TPL = 'attachment; filename="{0:s}"'

CONTENT_JSON = 'application/json'
CONTENT_HTML = 'text/html'
CONTENT_PLAIN = 'text/plain'

DEFAULT_HEADERS = {
  HEADER_CONTENT_TYPE: CONTENT_HTML,
  HEADER_SERVER: 'Saucepan ({0:s})'.format(__version__),
}

HTTP_CODES = httplib.responses.copy()
HTTP_CODES[418] = "I'm a teapot"  # RFC 2324
HTTP_CODES[428] = "Precondition Required"
HTTP_CODES[429] = "Too Many Requests"
HTTP_CODES[431] = "Request Header Fields Too Large"

HTTP_CODE_RANGES = {1: 'Continue', 2: 'Success', 3: 'Redirect', 4: 'Request Error', 5: 'Server Error'}


class HttpProtocolError(Exception):  # raise on http-spec violation
  pass


def get_random_string(size, encode='hex', factor=2):
  if encode:
    return os.urandom(1 + size / factor).encode(encode)[:size]
  else:
    return os.urandom(size)


def get_default_http_message(code):
  c = int(code) / 100
  return HTTP_CODE_RANGES.get(c, None)


def http_status(code, message=None):
  code = int(code)
  print "HTTP STATUS CALL !",code,message
  if message is None:
    message = HTTP_CODES.get(code, None)
    if message is None:
      message = get_default_http_message(code)
      if message is None:
        message = 'http'  # any better ideas ?
  return "{0} {1}".format(code, message)


# useful stuff

def _read_iter_blocks(read_fn, size, block_size=2048):
  while True:
    if block_size > size:
      block_size = size
    block = read_fn(block_size)
    if not block or len(block) == 0:
      return
    yield block
    size -= len(block)
    if size <= 0:
      return

def _read_iter_chunked(read_fn, size):
  while True:
    return False
  # TODO : implement me !


def _regex_get_args_kwargs(exp, mo):
  idx = exp.groupindex.values()
  groups = mo.groups()
  kwargs = mo.groupdict()
  args = []
  for i in range(len(groups)):
    if (i + 1) not in idx:  # not a groupdict
      args.append(groups[i])
  return args, kwargs

def _tokenize_query_str(s, probe=True, eq_char='=', sep_char='&'):
  if probe:
    tmp = s[:100]
    if eq_char in tmp or sep_char in tmp:
      pass # ok !
    else:
      return # None
  for chunk in s.split(sep_char):
    if eq_char in chunk:
      yield chunk.split(eq_char,1)
    else:
      yield [chunk, None]



def _parse_range(value, max_len=-1):
  # http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.12
  # The only range unit defined by HTTP/1.1 is "bytes".
  range_str_bytes = 'bytes='
  if range_str_bytes not in value:
    raise Exception("Invalid 'range' header syntax !")
  _, value = value.split(range_str_bytes, 1)
  r = []
  for rng in value.split(","):
    if '-' not in rng:
      raise HttpProtocolError("Invalid 'range' header syntax!")
    a, b = rng.split('-')
    if a == '' and b == '':
      raise HttpProtocolError("Invalid 'range' header syntax!")
    if a == '':
      a = 0
    else:
      a = int(a)
    if b == '':
      b = max_len
    else:
      b = int(b)
    if max_len > 0:
      if a > max_len:
        a = max_len
      if b > max_len:
        b = max_len
    if b > 0:  # handle -1 as unknown 'end' of data
      if a > b:
        raise HttpProtocolError("Invalid 'range' header syntax !")
    r.append([a, b])
  return r


#
# -------------- generic server snap-in  -----
#


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
    logging.debug("Starting WSGIRef simple server on {0}:{1}".format(host, port))
    self.server = ref_srv.make_server(host, port, wsgi_app, srv_class, hnd_class)
    try:
      self.server.serve_forever()
    except KeyboardInterrupt:
      self.server.server_close()


#
# -------------- HTTP STUFF  -----
#

class LastUpdatedOrderedDict(OrderedDict):
  def __setitem__(self, key, value, dict_setitem=dict.__setitem__):
    if key in self:
      del self[key]
    OrderedDict.__setitem__(self, key, value, dict_setitem=dict_setitem)


class CaseInsensitiveHttpEnv(object):
  """
  Object that allow to access to env storage (http headers + other metadata)
  in case-insensitive way
  """

  _extra_keys = ('CONTENT_TYPE', 'CONTENT_LENGTH')
  _env = None

  def __init__(self, env):
    self._env = env
    # for k,v in env.iteritems():
    #  print k,v

  def __getitem__(self, item):
    return self.get(item, None)

  def get(self, item, default=None, require=False):
    item = str(item)
    item = item.upper()
    if item.startswith("HTTP_"):
      # well, user knows _really_ good what he needs
      # else: we need help him a little
      pass
    if item in self._extra_keys: # let them pass ;-)
      pass
    #elif item == 'METHOD':  # special metadata #1
    #  item = 'REQUEST_METHOD'
    #elif item == 'PROTOCOL':  # special metadata #2
    #  item = 'SERVER_PROTOCOL'
    else:
      item = "HTTP_" + item
    val = self._env.get(item, None)
    if val is None:
      if require:
        raise KeyError(item)
      return default
    return val

  def has(self, key):
    return self.get(key) is not None

  def check(self, key, val):
    cur_val = self.get(key, default=None)
    if cur_val is None:
      return False
    if isinstance(val, list):
      if cur_val in val:
        return True
    return cur_val == val


class HttpMessage(object):  # meta-object
  body = ''


class HttpRequest(HttpMessage):
  files = {}
  post_vars = {}
  get_vars = {}

  def __init__(self, env):
    self.env = env
    #for k,v in env.iteritems():
    #  print k,' = ',v
    self.headers = CaseInsensitiveHttpEnv(env)
    self.verb = env.get('REQUEST_METHOD')
    self.method = self.verb  # You call it verb, I call it method
    self.protocol = env.get('SERVER_PROTOCOL')
    self.path = env.get('PATH_INFO')
    self.host = env.get('HTTP_HOST')
    self.query_string = env.get('QUERY_STRING')
    self.content_type = env.get('CONTENT_TYPE')
    self.wsgi_input = env.get('wsgi.input')
    self.is_chunked = False
    enc = self.headers.get('TRANSFER_ENCODING','').lower()
    if 'chunk' in enc: # well, it is so pro ;-)
      self.is_chunked = True
    l = env.get('CONTENT_LENGTH','')
    if len(l) < 1:
      self.content_length = 0
    else:
      self.content_length = int(l)
    self.body = io.BytesIO()

  def parse(self): # parse body, post, get, files and cookies.
    if self.content_length > MAX_CONTENT_SIZE: # declared size too large ...
      raise Http4xx(httplib.REQUEST_ENTITY_TOO_LARGE)
      # do not event bother ;-)
    if self.content_length > 0:
      try: # re-parse body, fill BytesIO ;-)
        fn = _read_iter_chunked if self.is_chunked else _read_iter_blocks
        for block in fn(self.wsgi_input.read, self.content_length):
          self.body.write(block)
        self.body.seek(0)
      except:
        pass # TODO : crash ? or keep silent ?
    for k,v in _tokenize_query_str(self.query_string, probe=False):
      print "GET ",k," = ",v
      self.get_vars[k] = v
    if 'multipart/' not in self.content_type: # or check for application/x-www-form-urlencoded ?
      # split data from body into POST vars
      for k,v in _tokenize_query_str(self.get_body()):
        print "POST ",k," = ",v
        self.post_vars[k] = v
    else: # handle multipart POST data
      pass
    # notes to myself :
    #  - try to keep all data in body (especially large blobs)
    #    by storing offset to variables in FILES array (access wrappers ?)
    #


  def get_body(self):
    if self.content_length < 0:
      self.content_length = MAX_CONTENT_SIZE
    self.body.seek(0)
    return self.body.read(self.content_length)

  def post(self, key, default=None, required=False):
    pass

  def get(self, key, default=None, required=False):
    pass

  def arg(self, key, default=None, required=False):
    pass

  def uri(self, host=False):
    if host:
      return self.host + self.path
    else:
      return self.path


class HttpResponse(HttpMessage):
  status_code = 200
  status_message = None
  headers = LastUpdatedOrderedDict()
  fix_content_length = True
  # http_version = '' <- will not be used ?

  def __init__(self):  # , version='HTTP/1.1'):
    # self.http_version = version
    pass

  def status(self, code, message=None):
    self.status_code = code
    self.status_message = message

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
      self.headers[HEADER_CONTENT_LENGTH] = str(s)


class TheContext(object):
  def __init__(self, env):
    self.request = HttpRequest(env)
    self.response = HttpResponse()  # version=self.request.version)
    self.env = env


#
# -------------- ROUTER  -----
#

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
    logging.debug("Adding new route [testable={0:s}] ".format(str(testable)))
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
    logging.warning("No valid route found ! Try default ...")
    self._default_route(ctx)
    return ctx

#
# -------------- 'Default' Router class  -----
#


# should we move this inside DefaultRouter class ??

ROUTE_CHECK_UNDEF = None
ROUTE_CHECK_ALWAYS = 0xff
ROUTE_CHECK_STR = 1
ROUTE_CHECK_SIMPLE = 2
ROUTE_CHECK_REGEX = 3
ROUTE_CHECK_CALL = 4
ROUTE_GENERATOR = 5
DEFAULT_ROUTE_TYPE = ROUTE_CHECK_SIMPLE
ROUTE_ALWAYS = None  # <- special 'testble' value

METHOD_GET = ['GET']
METHOD_POST = ['POST']


def _default_router_do_call(ctx, fn, a, kw):
  data = fn(ctx, *a, **kw)
  if data:
    if ctx.response.body:
      ctx.response.body += data
      #                 ^- append, NOT replace !
      # this would raise exception, if resp.body is already set,
      # and called function return incompatible type (ex. str + dict )
    else:
      ctx.response.body = data  # <- this should work if we return dict,


# one can implement other router-type class, this provide
# basic, but complex functionality

class DefaultRouter(AbstractRouter):
  _SIMPLE_CHAR_SET = 'a-zA-Z0-9'
  _SIMPLE_RE_FIND = r'<([^>]*)>'
  _SIMPLE_RE_REPLACE = r'(?P<\1>[' + _SIMPLE_CHAR_SET + ']*)'
  _type_mapping = {}

  def setup(self):
    # TODO : rewrite dict routes to classes ? (need to benchmark !)
    self._type_mapping = {
      ROUTE_CHECK_ALWAYS: self._test_always,
      ROUTE_CHECK_STR: self._test_str,
      ROUTE_CHECK_SIMPLE: self._test_re,
      ROUTE_CHECK_REGEX: self._test_re,
      ROUTE_CHECK_CALL: self._test_call,
      ROUTE_GENERATOR: self._test_generator,
    }

  @staticmethod
  def _test_always(ctx, testable=None, target=None, **kw):
    _default_router_do_call(ctx, target, [], kw)
    return True

  @staticmethod
  def _test_str(ctx, testable='', target=None, **ex):
    uri = ctx.request.uri()
    if uri == testable:
      _default_router_do_call(ctx, target, [], ex)
      return True
    return False

  @staticmethod
  def _test_re(ctx, testable=None, target=None, _re=None, **ex):
    uri = ctx.request.uri()
    mo = _re.match(uri)
    if not mo:
      return False
    args, kwargs = _regex_get_args_kwargs(_re, mo)
    ex.update(kwargs)
    _default_router_do_call(ctx, target, args, ex)
    return True

  @staticmethod
  def _test_call(ctx, testable=None, target=None, **ex):
    ret_val = testable(ctx, **ex)
    args = []
    if isinstance(ret_val, tuple) or isinstance(ret_val, list):
      bool_val = ret_val[0]
      args = ret_val[1:]
    else:
      bool_val = ret_val
    if bool_val:
      _default_router_do_call(ctx, target, args, route)
      return True
    return False

  @staticmethod
  def _test_generator(ctx, testable=None, target=None, **ex):
    ret_val = testable(ctx, **ex)
    if ret_val is None:
      return False
    args = []
    if isinstance(ret_val, tuple) or isinstance(ret_val, list):
      func = ret_val[0]
      args = ret_val[1:]
    else:
      func = ret_val
    _default_router_do_call(ctx, func, args, route)
    return True

  def add_entry(self, testable=ROUTE_ALWAYS, **kw):  # add default testable value
    AbstractRouter.add_entry(self, testable, **kw)

  def _pre_process(self, **kw):
    # TODO : this could return object with proper methods/values/etc
    testable = kw.get('testable')  # <- required argument
    target = kw.get('target', None)  # <- ref to func || None
    route_type = kw.get('route_type', ROUTE_CHECK_UNDEF)
    if 'headers' not in kw:
      kw['headers'] = []
    else:
      if not isinstance(kw['headers'], list):
        kw['headers'] = []

    # convert al check_%s key into required header names
    for key in kw.keys():
      if key.startswith("check_"):
        item = key.split("_", 1)[1]
        kw['headers'].append((item, kw[key]))
        del kw[key]

    if route_type == ROUTE_CHECK_UNDEF:
      logging.debug("Route type is not set. Guessing ...")
      if testable is ROUTE_ALWAYS:
        route_type = ROUTE_CHECK_ALWAYS
      elif isinstance(testable, basestring):
        if "<" in testable:
          route_type = ROUTE_CHECK_SIMPLE
        else:
          route_type = ROUTE_CHECK_STR
      if callable(testable):  # callable can be check or generator
        if target is None:
          route_type = ROUTE_GENERATOR
        else:
          route_type = ROUTE_CHECK_CALL
      kw['route_type'] = route_type
      logging.debug("Route type after guess: {0:d}".format(route_type))
    else:
      # "* Route type already set to :", route_type
      pass

    # setup proxy function to perform test.
    # Setting this here allow to skip another switch-case construct in try_route
    kw['_callable'] = self._type_mapping.get(route_type, None)
    if route_type == ROUTE_CHECK_REGEX:
      kw['_re'] = re.compile(testable)
    if route_type == ROUTE_CHECK_SIMPLE:
      _tmp = re.sub(self._SIMPLE_RE_FIND, self._SIMPLE_RE_REPLACE, testable)
      kw['_re'] = re.compile(_tmp)
    return kw

  def try_route(self, ctx, _callable=None, headers=None, route_type=None, **args):
    if headers and len(headers) > 0:
      for key, val in headers:
        if not ctx.request.headers.check(key, val):
          return False
    if _callable and callable(_callable):
      return _callable(ctx, **args)
    else:
      logging.error("Ouch! problem with _callable !")


# 3xx and 4xx "exceptions",
# use them to stop function execution and return proper http answer

# TODO: merge them to HttpEndNow(code,message,...) ?
# this would allow user to raise httpEnd(200) to stop processing in middle of nowhere
# not only 3xx and 4xx

class Http3xx(Exception):
  def __init__(self, target, code=httplib.MOVED_PERMANENTLY):
    Exception.__init__(self, "HTTP Redirect")
    self.target = target
    self.code = code


class Http4xx(Exception):
  def __init__(self, code, info=None):
    if info is None:
      info = get_default_http_message(code)
    if info is None:
      info = "Error"
    Exception.__init__(self, "HTTP Error: {0:d} {1:s}".format(code, info))
    self.code = code
    self.info = info


# 3xx and 4xx handlers

def _http_4xx_handler(_, ctx, error):
  ctx.response.status(error.code, error.info)
  return "{0:d} : {1:s}".format(error.code, error.info)


def _http_3xx_handler(_, ctx, error):
  ctx.response.status(error.code)
  ctx.response.headers[HEADER_LOCATION] = error.target
  return '<a href="{0:s}">Moved : {0:s}</a>'.format(error.target)


# Exception handlers :

def _silent_error_handler(ctx, _):
  ctx.response.headers[HEADER_CONTENT_TYPE] = CONTENT_HTML
  return "500: server fail !"


def _verbose_error_handler(ctx, _):
  import traceback
  import sys

  info = sys.exc_info()
  traceback.print_exception(*info)
  body = "SERVER FAIL:<br><pre>\n"
  body += '\n'.join(traceback.format_exception(*info))
  body += "\n\n</pre>"
  ctx.response.headers[HEADER_CONTENT_TYPE] = CONTENT_HTML
  return body


def _default_request_handler(ctx):
  ctx.response.status_code = 404
  return "Not found!"


HOOK_PRE = 'pre'
HOOK_POST = 'post'
POSSIBLE_HOOKS = [HOOK_PRE, HOOK_POST]


class CookingPot(object):
  """
   >>main<< class, glues everything ...
  """
  _write_using_writer = False
  router = DefaultRouter()
  be_verbose = True
  auto_json = True
  _exception_handlers = []
  handle_3xx = _http_3xx_handler
  handle_4xx = _http_4xx_handler
  pre_hooks = []
  post_hooks = []

  def __init__(self, router_class=None):
    logging.debug("Main object init")
    if router_class:
      self.router = router_class()
    self.router.default = _default_request_handler

  def hook(self, h_type, *a, **kw):
    if h_type not in POSSIBLE_HOOKS:
      raise Exception("Invalid hook type! {0:s} not in {1:s}".format(h_type, str(POSSIBLE_HOOKS)))

    def _wrapper(f):
      entry = dict(func=f, args=a, kwargs=kw)
      if h_type == HOOK_PRE:
        self.pre_hooks.append(entry)
      elif h_type == HOOK_POST:
        self.post_hooks.append(entry)

    return _wrapper

  def handle_exception(self, ex_type, **kw):
    def _wrapper(f):
      self.add_exception_handler(ex_type, f, **kw)

    return _wrapper

  def add_exception_handler(self, ex_type, fn, **kw):
    self._exception_handlers.append(
      dict(ex_type=ex_type, handler=fn, kwargs=kw)
    )

  def route(self, testable, **kw):
    def _wrapper(f):
      self.add_route(testable, target=f, **kw)

    return _wrapper

  def add_route(self, testable, target=None, **kw):
    self.router.add_entry(testable, target=target, **kw)

  def _handle_error(self, ctx, error):
    ctx.response.status(httplib.INTERNAL_SERVER_ERROR)  # 500
    for entry in self._exception_handlers:
      if isinstance(error, entry['ex_type']):
        return entry['handler'](ctx, error, **entry['kwargs'])
    if self.be_verbose:
      return _verbose_error_handler(ctx, error)
    else:
      return _silent_error_handler(ctx, error)

  def wsgi_handler(self, environ, start_response):
    logging.debug('WSGI handler called ...')
    exc_info = None
    ctx = TheContext(environ)
    for k, v in DEFAULT_HEADERS.iteritems():
      ctx.response.headers[k] = v
    try:
      # one will say that is insane, but it handle the situation that
      # exception handler will fail somehow ....
      try:
        ctx.request.parse()
        for _h in self.pre_hooks:
          if callable(_h['func']):
            logging.debug("Calling PRE hook : {0:s}".format(str(_h)))
            _h['func'](ctx, *_h['args'], **_h['kwargs'])
        self.router.select_route(ctx)
        for _h in self.post_hooks:
          if callable(_h['func']):
            logging.debug("Calling POST hook : {0:s}".format(str(_h)))
            _h['func'](ctx, *_h['args'], **_h['kwargs'])

      except Http3xx as ex:
        ctx.response.body = self.handle_3xx(ctx, ex)
      except Http4xx as ex:
        ctx.response.body = self.handle_4xx(ctx, ex)
      except Exception as ex:
        ctx.response.body = self._handle_error(ctx, ex)
    except Exception as epic_fail:
      logging.error("EPIC FAIL : " + str(epic_fail))
      ctx.response.body = "CRITICAL ERROR"
      ctx.response.status(httplib.INTERNAL_SERVER_ERROR)  # 500
    ctx.response.finish()
    headers = ctx.response.get_headers()
    status = ctx.response.get_status()
    body_writer = start_response(status, headers, exc_info)
    if self._write_using_writer:
      if callable(body_writer):
        body_writer(ctx.response.body)
        return ''
      else:
        return ctx.response.body
    else:
      return ctx.response.body


pan = CookingPot()

# utils:


class MultipartElement(object):
  def __init__(self, content, fields=None):
    self.content = content
    self.fields = fields if fields else {}


def make_multipart(ctx, parts, mp_type='form-data', marker=None, fields=None):
  if marker is None:
    marker = 'MARK' + get_random_string(20)
  if fields is None:
    fields = {}
  body = ''
  for element in parts:
    if not isinstance(element, MultipartElement):
      continue
    body += '--' + marker + '\n'
    merged = fields.copy()
    merged.update(element.fields)
    for k, v in merged.iteritems():
      body += '{0:s}: {1:s}'.format(k, v)
    body += '\n'
    body += element.content + '\n'
  body += '--' + marker + '--\n'
  ctx.response.headers[HEADER_CONTENT_TYPE] = 'multipart/{0:s}; boundary={1:s}'.format(mp_type, marker)
  ctx.response.body = body


# plugin-like hooks,
# disabled by default to allow faster processing ...


def enable_auto_json():
  # <-- move this to "extension package?"
  # Why? not everybody need that ! It cause
  @pan.hook(HOOK_PRE)
  def _auto_json_pre(ctx):
    ctx.do_auto_json = True

  @pan.hook(HOOK_POST)
  def _auto_json_post(ctx):
    if not ctx.do_auto_json:
      return
    if isinstance(ctx.response.body, dict) or isinstance(ctx.response.body, list):
      logging.debug('Apply auto JSON (in hook)')
      body = json.dumps(ctx.response.body)
      ctx.response.headers[HEADER_CONTENT_TYPE] = CONTENT_JSON
      ctx.response.body = body


def enable_auto_head_handler():
  @pan.hook(HOOK_POST)
  def _handle_head(ctx):
    if not ctx.request.verb == 'HEAD':
      return
    ctx.response.fix_content_length = False
    ctx.response.headers[HEADER_CONTENT_LENGTH] = len(ctx.response.body)
    ctx.response.body = ''


def enable_auto_range_handler():  # <- do we need this ?
  @pan.hook(HOOK_PRE)
  def _handle_range_pre(ctx):
    ctx.do_range = True

  @pan.hook(HOOK_POST)
  def _handle_range_post(ctx):
    if not ctx.do_range:
      return
    header_value = ctx.request.headers.get(HEADER_RANGE)
    if not header_value or len(header_value) == 0:
      return
    org_size = len(ctx.response.body)
    ranges = _parse_range(header_value, max_len=org_size)
    if not header_value or len(header_value) == 0:
      return
    ctx.response.status(httplib.PARTIAL_CONTENT)  # 206, avoid magic constant ;-)
    if len(ranges) == 1:
      a, b = ranges[0]
      ctx.response.body = ctx.response.body[a:b]
      ctx.response.headers[HEADER_CONTENT_RANGE] = 'bytes {0}-{1}/{2}'.format(a, b, org_size)
      return
    # else len > 1
    parts = []
    for ab in ranges:  # overlapping ranges ? we do not care ;-)
      parts.append(MultipartElement(ctx.response.body[ab[0]:ab[1]]))
    make_multipart(ctx, parts, 'byteranges')


def static_handler(ctx, filename=None, static_dir='./', mime=None, encoding=None, save_as=None, last=True):
  real_static = os.path.abspath(static_dir)
  real_path = os.path.abspath(os.path.join(static_dir, filename))
  logging.debug("Try static file access : {0:s} ".format(real_path))
  if not real_path.startswith(real_static):
    raise Http4xx(httplib.FORBIDDEN)  # 403
  if not os.path.exists(real_path):
    raise Http4xx(httplib.NOT_FOUND)  # 404
  if not os.path.isfile(real_path):
    raise Http4xx(httplib.NOT_FOUND)  # 404
  if not os.access(real_path, os.R_OK):
    raise Http4xx(httplib.FORBIDDEN)  # 403
  if hasattr(ctx, 'do_auto_json'):
    ctx.do_auto_json = False  # <- skip processing
  if mime is None:
    mime, enc = mimetypes.guess_type(real_path)
    if encoding is None and enc is not None:
      encoding = enc
  if encoding:
    ctx.response.headers[HEADER_CONTENT_ENCODING] = encoding
  if save_as is not None:
    ctx.response.headers[HEADER_CONTENT_DISPOSITION] = SAVE_AS_TPL.format(save_as)
  if last:
    # http://tools.ietf.org/html/rfc2616#section-14.29
    # http://tools.ietf.org/html/rfc2616#section-3.3
    f_stat = os.stat(real_path)
    lm_str = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(f_stat.st_mtime))
    ctx.response.headers[HEADER_LAST_MODIFIED] = lm_str

  # TODO :
  # range ?
  # content-range ?
  # content-length ?
  return open(real_path, 'r').read()


def register_static_file_handler(url_prefix='/static/', static_dir='./static/'):
  pan.add_route(url_prefix + "(.*)", target=static_handler, static_dir=static_dir, route_type=ROUTE_CHECK_REGEX)

# expose in globals, so we can use @decorator
route = pan.route


def _wsgi_handler(environ, start_response):
  return pan.wsgi_handler(environ, start_response)


def wsgi_interface():
  return _wsgi_handler

# expose WSGI handler
application = wsgi_interface()


def run(server_class=None, **opts):
  logging.debug("Preparing WSGI server ... ")
  if server_class is None:
    server_class = WSGIRefServer
  handle = server_class(**opts)
  logging.debug("Running server ... ")
  handle.run(_wsgi_handler)


if __name__ == '__main__':
  logging.warn("Running standalone ?")
  run()

  # end
  # # TODO:
  # # add support for middleware (pre-request | post-request)
