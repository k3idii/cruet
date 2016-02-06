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
import string

from Cookie import SimpleCookie as CookiesDefaultContainer
from Cookie import Morsel as CookiesDefaultElement

# is this present on al os ?
import mimetypes

__author__ = 'KeiDii'
__version__ = '0.41'
__license__ = 'MIT'

DEFAULT_LISTEN_HOST = '0.0.0.0'
DEFAULT_LISTEN_PORT = 8008

MAX_CONTENT_SIZE = 1 * 1024 * 1024  # 1 MB

# ~~ const strings ~~

SERVER_NAME = "SaucePan"

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
HEADER_SET_COOKIE = 'Set-Cookie'

# common headers values
SAVE_AS_TPL = 'attachment; filename="{0:s}"'

CONTENT_JSON = 'application/json'
CONTENT_HTML = 'text/html'
CONTENT_PLAIN = 'text/plain'

HTTP_CODES = httplib.responses.copy()
HTTP_CODES[418] = "I'm a teapot"  # RFC 2324
HTTP_CODES[428] = "Precondition Required"
HTTP_CODES[429] = "Too Many Requests"
HTTP_CODES[431] = "Request Header Fields Too Large"

HTTP_CODE_RANGES = {1: 'Continue', 2: 'Success', 3: 'Redirect', 4: 'Request Error', 5: 'Server Error'}


class HttpProtocolError(Exception):  # raise on http-spec violation
  pass


_ALLOW_LAZY_PROPERTY_SET = False


class LazyProperty(property):
  def __init__(self, func, doc=None):
    super(LazyProperty, self).__init__(func)
    self._func = func
    self.__doc__ = doc or func.__doc__
    self._name = func.__name__  # no extra 'name' as arg yet, useless
    self._flag = "_got_{}".format(self._name)

  def __set__(self, instance, val):
    if _ALLOW_LAZY_PROPERTY_SET:
      instance.__dict__[self._name] = val
      if not hasattr(instance, self._flag):
        setattr(instance, self._flag, 1)
    else:
      raise AttributeError("Can't set value to lazy attribute !")

  def __get__(self, instance, class_type=None):
    if instance is None:
      return False  # or raise error ?
    if hasattr(instance, self._flag):
      return instance.__dict__[self._name]
    value = self._func(instance)  # replace !
    instance.__dict__[self._name] = value
    setattr(instance, self._flag, 1)
    return value


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


def _read_iter_chunks(read_fn, max_size):

  def _read_till(fn, stop_at='\n', max_bytes=10):
    b = ''
    n = 0
    if max_bytes == -1:
      while True:
        c = fn(1)
        n += 1
        if c == stop_at:
          return b, n
        b += c
    else:
      while max_bytes > 0:
        c = fn(1)
        n += 1
        if c == stop_at:
          return b, n
        b += c
        max_bytes -= 1

  def _read_next_chunk_start(fn, sep=';'):
    n = 0
    buf, num_read = _read_till(fn, "\n")
    if sep in buf:
      size, extension = buf.strip().split(sep, 1)
      size = int(size, 16)
      # TODO: handle params
    else:
      size = int(buf.strip(), 16)
    return size, num_read

  while max_size > 0:
    block_size, read_bytes = _read_next_chunk_start(read_fn)
    max_size -= read_bytes
    # TODO: check if max_size > block_size !
    if block_size > max_size:
      raise Http4xx(httplib.REQUEST_ENTITY_TOO_LARGE, "Max body size exceed !")
    if block_size == 0:
      return  # TODO : read trailer
    else:
      chunk = ''
      while block_size > 0:
        part = read_fn(block_size)
        block_size -= len(part)
        max_size -= len(part)
        chunk += part
      yield chunk
      _read_till(read_fn, '\n')  # should read 2 chars !


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
      pass  # ok !
    else:
      return  # None

  for chunk in s.split(sep_char):
    if eq_char in chunk:
      yield chunk.split(eq_char, 1)
    elif chunk and len(chunk) > 0:
      yield [chunk, None]
    else:
      pass


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

# this implements "response" headers container.
# TODO: We should re-write this to support multi-values per key (list)
class LastUpdatedOrderedDict(OrderedDict):
  def __setitem__(self, key, value, dict_setitem=dict.__setitem__):
    if key in self:
      del self[key]
    OrderedDict.__setitem__(self, key, value, dict_setitem=dict_setitem)


class DictAsObject(dict):  # prototype for settings ?
  def __getattr__(self, item):
    return self.__getitem__(item)

  def __setattr__(self, key, value):
    return self.__setitem__(key, value)


def str_to_env_key(name, extra_keys=None):
  name = str(name).upper()
  if name.startswith("HTTP_") or (extra_keys and name in extra_keys):
    return name
  return "HTTP_" + name


# decorator
def fix_kwarg(kwarg_name, func, *func_a, **func_kw):  # <- so awesome !
  def _wrap1(f):
    def _wrap2(*a, **kw):
      if kwarg_name in kw:
        kw[kwarg_name] = func(kw[kwarg_name], *func_a, **func_kw)
      else:
        idx = f.func_code.co_varnames.index(kwarg_name)
        a = list(a)
        a[idx] = func(a[idx], *func_a, **func_kw)
      return f(*a, **kw)

    if kwarg_name not in f.func_code.co_varnames:
      raise Exception("{0} not in arg names of {1}".format(kwarg_name, str(f)))
    return _wrap2

  return _wrap1


class CaseInsensitiveEnv(object):
  """
  Object that allow to access to env storage (http headers + other metadata)
  in case-insensitive way
  """
  _extra_keys = ('CONTENT_TYPE', 'CONTENT_LENGTH')
  _env = None

  def __init__(self, env):
    self._env = env

  def __getitem__(self, item):
    return self.get(item, None)

  @fix_kwarg('key', str_to_env_key, _extra_keys)
  def get(self, key, default=None, require=False):
    val = self._env.get(key, None)
    if val is None:
      if require:
        raise KeyError(key)
      return default
    return val

  @fix_kwarg('key', str_to_env_key, _extra_keys)
  def has(self, key):
    return self._env.get(key) is not None

  @fix_kwarg('key', str_to_env_key, _extra_keys)
  def check(self, key, val):
    cur_val = self.get(key, default=None)
    if cur_val is None:
      return False
    if isinstance(val, list):
      if cur_val in val:
        return True
    return cur_val == val

  def __str__(self):  # debug me :-)
    c = []
    for k in self._env:
      if k.startswith('HTTP_'):
        c.append((k[5:], self._env[k]))
    return json.dumps(c)


MULTIDICT_GET_ONE = 1
MULTIDICT_GET_ALL = 2


class CaseInsensitiveMultiDict(object):  # response headers container
  _storage_ = None

  def __init__(self, *a, **kw):
    self._storage_ = dict()
    if len(a) > 0:
      if isinstance(a[0], dict):
        for k, v in a[0].iteritems():
          self[k] = v
    else:
      for k, v in kw.iteritems():
        self[k] = v

  @fix_kwarg('key', string.upper)
  def get(self, key, mode=MULTIDICT_GET_ONE):
    if len(self._storage_[key]) > 0:
      if mode == MULTIDICT_GET_ONE:
        return self._storage_[key][0]
      elif mode == MULTIDICT_GET_ALL:
        return self._storage_[key]
    return None

  @fix_kwarg('key', string.upper)
  def __setitem__(self, key, value):
    if key not in self._storage_:
      self._storage_[key] = list()
    self._storage_[key].append(value)

  @fix_kwarg('key', string.upper)
  def __getitem__(self, key):
    if len(self._storage_[key]) > 0:
      return self._storage_[key][0]
    return None

  def iteritems(self):
    for k, l in self._storage_.iteritems():
      for v in l:
        yield k, v


class HttpMessage(object):  # bare meta-object
  headers = {}
  body = None
  settings = None
  env = None

  def __init__(self, settings, env):
    self.settings = settings
    self.env = env
    self.on_init()

  def on_init(self):
    pass

  def prepare(self):
    pass


class HttpRequest(HttpMessage):
  files = None
  post = None
  get = None
  cookies = None
  body = None
  headers = None
  verb = method = None
  protocol = None
  path = None
  host = None
  content_type = None
  content_length = 0
  query_string = None
  is_chunked = False
  wsgi_input = None

  # TODO : I really need to rewrite this.

  def on_init(self):
    self.headers = CaseInsensitiveEnv(self.env)
    self.verb = self.env.get('REQUEST_METHOD')
    self.method = self.verb  # You call it verb, I call it method
    self.protocol = self.env.get('SERVER_PROTOCOL')
    self.path = self.env.get('PATH_INFO')
    self.host = self.env.get('HTTP_HOST')
    self.query_string = self.env.get('QUERY_STRING')
    self.content_type = self.env.get('CONTENT_TYPE')
    self.wsgi_input = self.env.get('wsgi.input')
    self.is_chunked = False
    enc = self.headers.get('TRANSFER_ENCODING', '').lower()
    print "ENCODING:" + enc
    if 'chunk' in enc:  # well, it is so pro ;-)
      self.is_chunked = True
      print "It is chunked !!!"
    l = self.env.get('CONTENT_LENGTH', '')
    if len(l) < 1:
      self.content_length = 0
    else:
      self.content_length = int(l)
    self.body = io.BytesIO()

  def prepare(self):
    """
      parse body, post, get, files and cookies.
      IDEA/NOTE to myself/TODO: implement variables initialization as lazy properties so they will
      be evaluated on first usage, not always !
      This should speed-up a little ...
    """
    self.cookies = {}
    self.post = {}
    self.get = {}
    self.files = {}
    # ~~~ BODY ~~~

    max_body_size = MAX_CONTENT_SIZE
    if self.content_length > 0:
      if self.content_length > MAX_CONTENT_SIZE:  # declared size too large ...
        raise Http4xx(httplib.REQUEST_ENTITY_TOO_LARGE)
      max_body_size = self.content_length
    try:  # re-parse body, fill BytesIO ;-)
      fn = _read_iter_chunks if self.is_chunked else _read_iter_blocks
      for block in fn(self.wsgi_input.read, max_body_size):
        self.body.write(block)
      self.body.seek(0)
    except Exception as ex:
      print "Problem @ read body ... ", str(ex), " silently pass ;-)"
      pass  # TODO : should we crash ? or keep silent ?
    # MOVE THIS TO LAZY METHODS
    cookie_str = self.env.get('HTTP_COOKIE', None)
    if cookie_str:
      tmp = self.settings.cookies_container_class(cookie_str)
      for c in tmp.values():
        self.cookies[c.key] = c.value
    # GET
    self._parse_query_string()
    # POST / FILES
    self._parse_body()

  def _parse_query_string(self):
    for k, v in _tokenize_query_str(self.query_string, probe=False):
      self.get[k] = v

  def make_php_like_variables(self):
    # your eyes will bleed, however ... 
    pass

  def get_body(self):
    if self.content_length < 0:
      self.content_length = MAX_CONTENT_SIZE
    self.body.seek(0)
    return self.body.read(self.content_length)

  def _parse_body(self):
    print "BODY", self.get_body()
    # override FILES and POST properties ...
    self.post = {}
    self.files = {}
    if 'multipart/' not in self.content_type:
      # or check for application/x-www-form-urlencoded ?
      # split data from body into POST vars
      for k, v in _tokenize_query_str(self.get_body(), probe=True):
        self.post[k] = v
    # ~~~ POST/body (multipart) ~~~
    else:  # TODO: !! handle/parse multipart !!
      print "MULTIPART SHIT!"
      print self.get_body()
      pass
      # notes to myself :
      #  - try to keep all data in body (especially large blobs)
      #    by storing offset to variables in FILES array (access wrappers ?)

  # @LazyPropertyWrapper(store=file_vars
  def xfiles(self):
    self._parse_body()
    return self.files

  # @LazyPropertyWrapper
  def xpost(self):
    self._parse_body()
    return self.post

  # @LazyPropertyWrapper
  def xcookies(self):
    cookie_str = self.env.get('HTTP_COOKIE', None)
    if cookie_str:
      self.cookies = self.settings.cookies_container_class(cookie_str)
    else:
      self.cookies = None
    return self.cookies

  def arg(self, key, default=None, required=False):
    if key in self.get:
      return self.get[key]
    if key in self.post:
      return self.post[key]
    if key in self.cookies:
      return self.cookies[key]
    if required:
      raise KeyError("Parameter [{0:s}] not found !".format(key))
    else:
      return default

  def uri(self, host=False):
    if host:
      return self.host + self.path
    else:
      return self.path


class HttpResponse(HttpMessage):
  status_code = 200
  status_message = None
  cookies = None
  headers = None
  fix_content_length = True

  # http_version = '' <- will not be used ?

  def prepare(self):
    # self.headers = LastUpdatedOrderedDict()
    self.headers = CaseInsensitiveMultiDict()
    self.cookies = self.settings.cookies_container_class()
    for k, v in self.settings.default_headers:
      self.headers[k] = v

  def set_status(self, code, message=None):
    self.status_code = code
    self.status_message = message

  def get_status(self):
    return http_status(self.status_code, self.status_message)

  def get_headers(self):
    r = []
    for k, v in self.headers.iteritems():
      r.append((k.title(), str(v)))
    return r

  def old_get_headers(self):  # return Camel-Case headers + values as list[]
    resp = []
    for k, v in self.headers.iteritems():
      if isinstance(v, list):
        for vv in v:
          resp.append((k.title(), str(vv)))
      else:
        resp.append((k.title(), str(v)))
    return resp

  def header(self, key, value):
    self.headers[key] = value

  def set_cookie(self, name, value=None, **kw):
    if len(value) > 4096:
      raise Exception('Cookie value to long')
    # c = self.settings.cookies_element_class()
    self.cookies[name] = value
    for k, v in kw.iteritems():
      self.cookies[name][k] = v
      # return c

  def finish(self):
    # store cookie
    if len(self.cookies) > 0:
      cookie_list = []
      for v in self.cookies.values():
        cookie_list.append(v.OutputString())
        # self.header(HEADER_SET_COOKIE, v.OutputString())
        self.headers[HEADER_SET_COOKIE] = v.OutputString()

        # self.headers[HEADER_SET_COOKIE] = cookie_list
    # calculate content-length header if not set
    if self.fix_content_length:
      s = len(self.body)
      self.headers[HEADER_CONTENT_LENGTH] = str(s)


class TheContext(object):
  def __init__(self, settings, env):
    self.settings = settings
    self.env = env
    self.request = HttpRequest(settings, env)
    self.response = HttpResponse(settings, env)  # version=self.request.version)

  def prepare(self):
    self.request.prepare()
    self.response.prepare()

  # I know this looks weird, but it is rly handy ;-)
  def cookie(self, name, *a, **kw):  # magic cookie set/get wrapper
    if len(kw) == 0 and len(a) == 0:
      return self.request.cookies.get(name, None)
    else:
      self.response.set_cookie(name, *a, **kw)
      #                                   ^- pass value as 1st arg


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
ROUTE_ALWAYS = None  # <- special 'testable' value

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
  _SIMPLE_RE_FIND = r'<([^>]+)>'
  _SIMPLE_RE_REPLACE = r'(?P<\1>[' + _SIMPLE_CHAR_SET + ']+)'
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
    print kw
    return kw

  def try_route(self, ctx, _callable=None, headers=None, route_type=None, method=None, **args):
    if method:
      if ctx.request.method not in method:
        return False
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

def http_4xx_handler(ctx, error):
  ctx.response.set_status(error.code, error.info)
  return "{0:d} : {1:s}".format(error.code, error.info)


def http_3xx_handler(ctx, error):
  ctx.response.set_status(error.code)
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


class TheSettings(object):
  cookies_container_class = CookiesDefaultContainer
  cookies_element_class = CookiesDefaultElement
  be_verbose = True
  default_headers = [
    [HEADER_CONTENT_TYPE, CONTENT_HTML],
    [HEADER_SERVER, '{0:s} (ver {1:s})'.format(SERVER_NAME, __version__)],
  ]

  def __init__(self, source=None):
    if source:
      self.load(source)

  def load(self, source):  # import dict
    for k, v in source.iteritems():
      setattr(self, k, v)


class CookingPot(object):
  """
   >>main<< class, glues everything ...
  """
  _write_using_writer = False
  router = DefaultRouter()
  _exception_handlers = []
  pre_hooks = []
  post_hooks = []
  settings = None

  def __init__(self, router_class=None, settings=None):
    logging.debug("Main object init")
    self.settings = TheSettings(settings)
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
    ctx.response.set_status(httplib.INTERNAL_SERVER_ERROR)  # 500
    for entry in self._exception_handlers:
      if isinstance(error, entry['ex_type']):
        return entry['handler'](ctx, error, **entry['kwargs'])
    if self.settings.be_verbose:
      return _verbose_error_handler(ctx, error)
    else:
      return _silent_error_handler(ctx, error)

  def wsgi_handler(self, environ, start_response):
    logging.debug('WSGI handler called ...')
    exc_info = None
    ctx = TheContext(self.settings, environ)
    try:
      # one will say that is insane, but it handle the situation that
      # exception handler will fail somehow ....
      try:
        ctx.prepare()
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
        ctx.response.body = http_3xx_handler(ctx, ex)
      except Http4xx as ex:
        ctx.response.body = http_4xx_handler(ctx, ex)
      except Exception as ex:
        ctx.response.body = self._handle_error(ctx, ex)
    except Exception as epic_fail:
      logging.error("EPIC FAIL : " + str(epic_fail))
      ctx.response.body = "CRITICAL ERROR"
      ctx.response.set_status(httplib.INTERNAL_SERVER_ERROR)  # 500
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
    ctx.response.set_status(httplib.PARTIAL_CONTENT)  # 206, avoid magic constant ;-)
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
