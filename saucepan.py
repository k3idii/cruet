# !/usr/bin/env python
# -*- coding: utf-8 -*-
#
import sys
is_python_3 = sys.version_info.major >= 3

from collections import OrderedDict
from abc import abstractmethod
import re
import time
import json
import binascii
import os
import os.path
import io
# import string

import cgi


if is_python_3 :
  import http.client as http_base
  from http.cookies import SimpleCookie as DefaultCookiesContainer
  from http.cookies import Morsel as DefaultCookiesElement
else:
  import httplib as http_base
  from Cookie import SimpleCookie as DefaultCookiesContainer
  from Cookie import Morsel as DefaultCookiesElement





# is this present on al os ?
import mimetypes

__author__ = 'KeiDii'
__version__ = '0.41'
__license__ = 'MIT'

DEFAULT_LISTEN_HOST = '0.0.0.0'
DEFAULT_LISTEN_PORT = 8008

MAX_CONTENT_SIZE = 1 * 1024 * 1024  # 1 MB

INVALID_CONTENT_LEN = -1

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

QUERY_STRING_SEP = '&'
QUERY_STRING_EQ = '='

CONTENT_JSON = 'application/json'
CONTENT_HTML = 'text/html'
CONTENT_PLAIN = 'text/plain'

HTTP_CODES = http_base.responses.copy()
HTTP_CODES[418] = "I'm a teapot"  # RFC 2324
HTTP_CODES[428] = "Precondition Required"
HTTP_CODES[429] = "Too Many Requests"
HTTP_CODES[431] = "Request Header Fields Too Large"

HTTP_CODE_RANGES = {1: 'Continue', 2: 'Success', 3: 'Redirect', 4: 'Request Error', 5: 'Server Error'}

# why -> cause logging is sloooow !
LOG_DEBUG = 4
LOG_INFO = 3
LOG_WARN = 2
LOG_ERROR = 1


class TinyLogger(object):
  level = LOG_DEBUG

  def debug(self, a):
    if self.level >= LOG_DEBUG:
      print("DEBUG: {0}".format(a))

  def info(self, a):
    if self.level >= LOG_INFO:
      print("INFO: {0}".format(a))

  def warn(self, a):
    if self.level >= LOG_WARN:
      print("WARN: {0}".format(a))

  def error(self, a):
    if self.level >= LOG_ERROR:
      print("ERROR: {0}".format(a))


the_logger = TinyLogger()

# </tiny logging>, one can replace the_logger w/ logging  ... will work ...

## If outside functions to speed things (one "if" less per call ;-)
if is_python_3:
  def __get_func_varnames(func):
    return func.__code__.co_varnames
  
  def _is_string(param):
    return isinstance(param, str)

else:
  def __get_func_varnames(func):
      return func.func_code.co_varnames

  def _is_string(param):
    return isinstance(param, basestring)



class HttpProtocolError(Exception):  # raise on http-spec violation
  pass


_ALLOW_LAZY_PROPERTY_SET = False


class LazyProperty(property):
  def __init__(self, func, doc=None):
    super(LazyProperty, self).__init__(func)
    self._func = func
    self.__doc__ = doc or func.__doc__
    self._name = func.__name__  # no extra 'name' as arg yet, useless
    self._flag = "_got_{0}".format(self._name)

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
      return binascii.hexlify(os.urandom(int(1 + size / factor)))[:size]
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


def _keyname_to_httpkeyame(name, extra_keys=None):
  name = str(name).upper()
  if name.startswith("HTTP_") or (extra_keys and name in extra_keys):
    return name
  return "HTTP_" + name


# decorator
def fix_kwarg(kwarg_name, func, *func_a, **func_kw):  # <- so awesome !
  def _wrap1(f):
    func_varnames = __get_func_varnames(f)
    def _wrap2(*a, **kw):
      if kwarg_name in kw:
        kw[kwarg_name] = func(kw[kwarg_name], *func_a, **func_kw)
      else:
        idx = func_varnames.index(kwarg_name)
        a = list(a)
        a[idx] = func(a[idx], *func_a, **func_kw)
      return f(*a, **kw)

    if kwarg_name not in func_varnames:
      print(func_varnames)
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

  @fix_kwarg('key', _keyname_to_httpkeyame, _extra_keys)
  def get(self, key, default=None, require=False):
    val = self._env.get(key, None)
    if val is None:
      if require:
        raise KeyError(key)
      return default
    return val

  @fix_kwarg('key', _keyname_to_httpkeyame, _extra_keys)
  def has(self, key):
    return self._env.get(key) is not None

  @fix_kwarg('key', _keyname_to_httpkeyame, _extra_keys)
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


class MultiValDict(object):  # response headers container
  _storage_ = None
  _key_mod = None

  def __init__(self, *a, **kw):
    self._storage_ = dict()
    if len(a) > 0:
      if isinstance(a[0], dict):
        for k, v in a[0].items():
          self[k] = v
    else:
      for k, v in kw.items():
        self[k] = v

  def get(self, key, default=None, mode=MULTIDICT_GET_ONE):
    if self._key_mod:
      key = self._key_mod(key)
    if len(self._storage_[key]) > 0:
      if mode == MULTIDICT_GET_ONE:
        return self._storage_[key][0]
      elif mode == MULTIDICT_GET_ALL:
        return self._storage_[key]
    return default

  def __setitem__(self, key, value):
    if self._key_mod:
      key = self._key_mod(key)
    if key not in self._storage_:
      self._storage_[key] = list()
    self._storage_[key].append(value)

  def __getitem__(self, key):
    if self._key_mod:
      key = self._key_mod(key)
    if len(self._storage_[key]) > 0:
      return self._storage_[key][0]
    return None

  def items(self):
    for k, l in self._storage_.items():
      for v in l:
        yield k, v


class CaseInsensitiveMultiDict(MultiValDict):  # response headers container

  def _key_mod(self, k):
    return str(k).upper()


def _parse_multipart(fd, boundary=None):
  def boo(s=''):
    the_logger.debug("Multipart-FAIL ! {0}".format(s))
    raise Http4xx(http_base.BAD_REQUEST, "Invalid Multipart/" + s)

  if boundary is None:
    raise Exception("Need to guess boundary marker ... not yet implemented !")
  if 1 > len(boundary) > 69:  # rfc1341
    boo("Invalid boundary marker size ")
  delimiter = "--{0}".format(boundary)
  close_delimiter_marker = '--'

  ln = fd.readline().strip()
  # print `ln`,`delimiter`
  if ln != delimiter:
    boo('invalid data - not delimiter')

  while True:

    meta = CaseInsensitiveMultiDict()

    while True:
      ln = fd.readline().strip()
      # print " -> Line : ", ln
      if ln == '':
        # print " -> EMPTY ! <- "
        break
      name, data = ln.split(": ", 1)
      val, opts = cgi.parse_header(data)
      # print "--> HEADERS :", name,' : ', val,' ; ', opts
      meta[name] = {'value': val, 'opts': opts}
      # entry_meta.append({'name':name, 'value':val, 'opts':opts})
    offset = fd.tell()
    # print "DATA AT OFFSET : ", offset

    if meta.get('Content-Disposition', None) is None:
      boo('No Content-Disposition!')

    r = ''
    while True:
      chunk = fd.readline()
      if chunk == '':
        # print "WTF"
        return
      # rint "CHUNK = ",`chunk`
      if chunk.startswith(delimiter):
        # r = 'some data'
        yield r.strip(), meta
        if chunk.strip().endswith(close_delimiter_marker):
          # print "END END"
          return
        else:
          break
      else:
        r += chunk

  yield "YO LO"
  print("PARSING STUFF")


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
      raise Http4xx(http_base.REQUEST_ENTITY_TOO_LARGE, "Max body size exceed !")
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

def _guess_str_is_querystring(s, qs_sep=QUERY_STRING_SEP, qs_eq=QUERY_STRING_EQ):
  return qs_sep in s or qs_eq in s

def _tokenize_query_str(s, qs_sep=QUERY_STRING_SEP, qs_eq=QUERY_STRING_EQ):
  for chunk in s.split(qs_sep):
    if len(chunk) == 0:
      pass
    elif qs_eq in chunk:
      yield chunk.split(qs_eq, 1)
    elif chunk and len(chunk) > 0:
      yield [chunk, None]
    else:
      pass

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
    the_logger.debug("Starting WSGIRef simple server on {0}:{1}".format(host, port))
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


class FileLike(object):
  def __init__(self):
    pass


class HttpMessage(object):  # bare meta-object
  headers = {}
  body = None
  env = None

  def __init__(self, env):
    self.env = env
    self.on_init()
    self.body = ''

  def on_init(self):  # called automatically by init, just to skip __init__ overriding
    pass

  def prepare(self):  # called manually by owner
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

  def on_init(self):
    self.headers = CaseInsensitiveEnv(self.env)
    self.verb = self.env.get('REQUEST_METHOD','')
    self.method = self.verb  # You call it verb, I call it method
    self.protocol = self.env.get('SERVER_PROTOCOL','')
    self.path = self.env.get('PATH_INFO','')
    self.host = self.env.get('HTTP_HOST','')
    self.query_string = self.env.get('QUERY_STRING','')
    self.content_type = self.env.get('CONTENT_TYPE','')
    self.wsgi_input = self.env.get('wsgi.input')
    self.is_chunked = False
    enc = self.headers.get('TRANSFER_ENCODING', '').lower()
    if 'chunk' in enc:  # well, it is so pro ;-)
      self.is_chunked = True
      the_logger.debug("It is chunked !!!")
    cl = self.env.get('CONTENT_LENGTH', None)
    if cl is None or cl == '':
      self.content_length = 0 # no header or empty header == 0
    else:
      try:
        int_cl = int(cl)
        if int_cl <= 0:
          int_cl = INVALID_CONTENT_LEN
        self.content_length = int_cl  
      except Exception as err:
        the_logger.debug("Fail to parse content-length: {0}".format(err))
        self.content_length = INVALID_CONTENT_LEN
    self.body = io.BytesIO()

  def prepare(self):
    """
      parse body, POST params, GET params, files and cookies.
      IDEA/NOTE to myself: implement variables initialization as lazy properties so they will
      be evaluated on first usage, not always !
      This should speed-up a little ...
    """
    self.cookies = {}
    self.post = {}
    self.get = {}
    self.files = {}
    # ~~~ BODY ~~~

    max_body_size = 0 # don't try to read in case of doubts
    if self.content_length != INVALID_CONTENT_LEN:
      if self.content_length > MAX_CONTENT_SIZE:  # declared size too large ...
        raise Http4xx(http_base.REQUEST_ENTITY_TOO_LARGE)
      max_body_size = self.content_length
    try:  # re-parse body, fill BytesIO ;-)
      fn = _read_iter_chunks if self.is_chunked else _read_iter_blocks
      for block in fn(self.wsgi_input.read, max_body_size):
        self.body.write(block)
      self.body.seek(0)
    except Exception as ex:
      the_logger.debug("Problem @ read body ... {0} | {1}".format(str(ex), " silently pass ;-)"))
      #TODO : should we crash ? or keep silent ?
    # TODO: MOVE THIS TO LAZY METHODS
    cookie_str = self.env.get('HTTP_COOKIE', None)
    if cookie_str:
      tmp = SETTINGS.cookies_container_class(cookie_str)
      for c in tmp.values():
        self.cookies[c.key] = c.value
    # GET
    self._parse_query_string()
    # POST / FILES
    self._parse_body()

  def _parse_query_string(self):
    for k, v in _tokenize_query_str(self.query_string):
      self.get[k] = v

  def get_body(self):
    if self.content_length == INVALID_CONTENT_LEN:
      # self.content_length = MAX_CONTENT_SIZE
      # ^-- this cused attempt to read from empty fd .. don't !
      # try to rescue the situation :
      return ''
    if self.content_length == 0:
      return ''
    self.body.seek(0)
    content = self.body.read(self.content_length)
    self.body.seek(0)
    return content

  def _parse_body(self):
    # override FILES and POST properties ...
    self.post = {}
    self.files = {}
    # or check for application/x-www-form-urlencoded ?
    if 'multipart/' in self.content_type:
      print("Multipart : {0}".format(self.get_body()))
      value, options = cgi.parse_header(self.content_type)
      for field in _parse_multipart(self.body, **options):
        data, opts = field
        # print "FIELD :", field, opts
        try:
          cd = opts.get('Content-Disposition')  # should be present, was checked in _parse_multipart
          name = cd['opts']['name']
          is_file = 'filename' in cd['opts']
        except Exception as err:
          raise Http4xx(400, "Fail to process body of http request: " + str(err))
        if is_file:
          self.files[name] = data
        else:
          self.post[name] = data
          # notes to myself :
          #  - try to keep all data in body (especially large blobs)
          # ~~~ POST/body (multipart) ~~~
          #    by storing offset to variables in FILES array (access wrappers ?)
    else:  # not a multi-part -> form !
      # split data from body into POST vars. TODO: handle this on first access to POST
      str_body = self.get_body()
      if _guess_str_is_querystring(str_body[:100]):  
        for k, v in _tokenize_query_str(self.get_body()):
          self.post[k] = v

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
      self.cookies = SETTINGS.cookies_container_class(cookie_str)
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
  body = ''
  fix_content_length = True

  # http_version = '' <- will not be used ?

  def prepare(self):
    self.headers = CaseInsensitiveMultiDict()
    self.cookies = SETTINGS.cookies_container_class()
    for k, v in SETTINGS.default_headers:
      self.headers[k] = v

  def set_status(self, code, message=None):
    self.status_code = code
    self.status_message = message

  def get_status(self):
    return http_status(self.status_code, self.status_message)

  def get_headers(self):
    r = []
    for k, v in self.headers.items():
      r.append((k.title(), str(v)))
    return r

  def old_get_headers(self):  # return Camel-Case headers + values as list[]
    resp = []
    for k, v in self.headers.items():
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
    for k, v in kw.items():
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

  def get_body(self):
    if is_python_3:
      return self.body.encode()
    else:
      return self.body


class TheContext(object):
  def __init__(self, env):
    self.env = env
    self.request = HttpRequest(env)
    self.response = HttpResponse(env)  # version=self.request.version)

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

  def _pre_process(self, testable, kw):
    return kw

  def _default_route(self, ctx, **kw):
    if callable(self.default):
      self.default(ctx, **kw)

  def add_entry(self, testable, **kw):
    the_logger.debug("Adding new route [testable={0:s}]".format(str(testable)))
    self._routes.append(self._pre_process(testable, kw))
    pass

  @abstractmethod
  def try_route(self, ctx, **route_args):
    pass

  def select_route(self, ctx):
    for rt in self._routes:
      if self.try_route(ctx, **rt):
        return ctx
    the_logger.warn("No valid route found ! Try default ...")
    self._default_route(ctx)
    return ctx


#
# -------------- 'Base' Routable class  (can be passed to router) -----
#

class RoutableClass(object):
  prefix = "do_"
  method_variable = "method"
  default = None

  def __init__(self):
    pass

  def always(self, ctx):
    pass

  def __call__(self, ctx, method=None, *a, **kw):
    method = kw.get(self.method_variable, None)
    if method is None:
      raise Exception("Method argument [{0}] is missing".format(self.method_variable))
    func_name = self.prefix + method
    func_ptr = getattr(self, func_name, self.default)
    if func_ptr and callable(func_ptr):
      self.always(ctx, *a, **kw)
      return func_ptr(ctx, *a, **kw)
    raise Exception("Fail to call method :" + str(method))


# should we move this inside DefaultRouter class ??

ROUTE_CHECK_UNDEF = None
ROUTE_CHECK_ALWAYS = 0xff
ROUTE_CHECK_STR = 1
ROUTE_CHECK_SIMPLE = 2
ROUTE_CHECK_REGEX = 3
ROUTE_CHECK_CALL = 4
ROUTE_GENERATOR = 5
ROUTE_CLASS = 6
DEFAULT_ROUTE_TYPE = ROUTE_CHECK_SIMPLE
ROUTE_ALWAYS = None  # <- special 'testable' value

METHOD_GET = ['GET']
METHOD_POST = ['POST']


def _default_router_do_call(ctx, fn, a, kw):
  the_logger.debug("Default router call ... ")
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

  def _pre_process(self, testable, kw):
    # TODO : this could return object with proper methods/values/etc

    kw['testable'] = testable
    target = kw.get('target', None)
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

    if isinstance(target, type):
      the_logger.debug("Creating instance of class ... ")
      # kw['_class'] = target
      kw['target'] = target()
      # if route_type != ROUTE_CLASS

    if route_type == ROUTE_CHECK_UNDEF:
      the_logger.debug("Route type is not set. Guessing ...")
      if testable is ROUTE_ALWAYS:
        route_type = ROUTE_CHECK_ALWAYS
      elif _is_string(testable):
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
      the_logger.debug("Route type after guess: {0:d}".format(route_type))
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

  def try_route(self, ctx, _callable=None, headers=None, route_type=None, method=None, **args):
    if method:
      if ctx.request.method not in method:
        return False
    if headers and len(headers) > 0:
      for key, val in headers:
        if not ctx.request.headers.check(key, val):
          return False
    if _callable and callable(_callable):
      the_logger.debug("ROUTER: calling {0:s}".format(str(_callable)))
      return _callable(ctx, **args)
    else:
      the_logger.error("Ouch! problem with _callable !")


# 3xx and 4xx "exceptions",
# use them to stop function execution and return proper http answer

# this would allow user to raise HttpEndNow(200) to stop processing in middle of nowhere
# not only 3xx and 4xx

class HttpEndNow(Exception):
  code = http_base.OK
  message = 'OK'

  def __init__(self, code=None, message=None, **kw):
    Exception.__init__(self, "HTTP End Processing")
    if code is not None:
      self.code = code
    if message is not None:
      self.message = message
    self.kw = kw

  def do_handle(self, ctx):
    ctx.response.status_code = self.code
    ctx.response.status_message = self.message
    return self.gracefully_handle(ctx, **self.kw)

  def gracefully_handle(self, ctx, **_):
    pass


class Http3xx(HttpEndNow):
  def gracefully_handle(self, ctx, target='/'):
    ctx.response.headers[HEADER_LOCATION] = target
    ctx.response.body = 'Moved to <a href="{0:s}">{0:s}</a> '.format(target)


class Http4xx(HttpEndNow):
  def gracefully_handle(self, ctx, **_):
    ctx.response.body = 'Error {0:d}'.format(self.code)


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


HOOK_BEFORE = 'pre'
HOOK_AFTER = 'post'
POSSIBLE_HOOKS = [HOOK_BEFORE, HOOK_AFTER]

SETTINGS = DictAsObject(
  cookies_container_class=DefaultCookiesContainer,
  cookies_element_class=DefaultCookiesElement,
  be_verbose=True,
  default_headers=[
    [HEADER_CONTENT_TYPE, CONTENT_HTML],
    [HEADER_SERVER, '{0:s} (ver {1:s})'.format(SERVER_NAME, __version__)],
  ],
)


class TheMainClass(object):
  """
   >>main<< class, glues everything ...
  """
  _write_using_writer = False
  router = DefaultRouter()
  _exception_handlers = []
  pre_hooks = []
  post_hooks = []

  def __init__(self, router_class=None):
    the_logger.debug("Main object init")
    if router_class:
      self.router = router_class()
    self.router.default = _default_request_handler

  def hook(self, h_type, *a, **kw):
    if h_type not in POSSIBLE_HOOKS:
      raise Exception("Invalid hook type! {0:s} not in {1:s}".format(h_type, str(POSSIBLE_HOOKS)))

    def _wrapper(f):
      entry = dict(func=f, args=a, kwargs=kw)
      if h_type == HOOK_BEFORE:
        self.pre_hooks.append(entry)
      elif h_type == HOOK_AFTER:
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
      self.router.add_entry(testable, target=f, **kw)
    return _wrapper

  def add_route(self, testable, target=None, **kw):
    self.router.add_entry(testable, target=target, **kw)

  def _handle_error(self, ctx, error):
    ctx.response.set_status(http_base.INTERNAL_SERVER_ERROR)  # 500
    for entry in self._exception_handlers:
      if isinstance(error, entry['ex_type']):
        return entry['handler'](ctx, error, **entry['kwargs'])
    if SETTINGS.be_verbose:
      return _verbose_error_handler(ctx, error)
    else:
      return _silent_error_handler(ctx, error)

  def wsgi_handler(self, environ, start_response):
    the_logger.debug('WSGI handler called ...')
    exc_info = None
    ctx = TheContext(environ)
    try:
      # one will say that is insane, but it handle the situation that
      # exception handler will fail somehow ....
      try:
        ctx.prepare()
        for _h in self.pre_hooks:
          if callable(_h['func']):
            the_logger.debug("Calling PRE hook : {0:s}".format(str(_h)))
            _h['func'](ctx, *_h['args'], **_h['kwargs'])
        self.router.select_route(ctx)
        for _h in self.post_hooks:
          if callable(_h['func']):
            the_logger.debug("Calling POST hook : {0:s}".format(str(_h)))
            _h['func'](ctx, *_h['args'], **_h['kwargs'])
      except HttpEndNow as ex:
        ex.do_handle(ctx)
      except Exception as ex:
        ctx.response.body = self._handle_error(ctx, ex)
    except Exception as epic_fail:
      the_logger.error("EPIC FAIL : " + str(epic_fail))
      ctx.response.body = "CRITICAL ERROR"
      ctx.response.set_status(http_base.INTERNAL_SERVER_ERROR)  # 500
    ctx.response.finish()
    headers = ctx.response.get_headers()
    status = ctx.response.get_status()
    body_writer = start_response(status, headers, exc_info)
    if self._write_using_writer and callable(body_writer):
      body_writer(ctx.response.get_body())
      return ['']
    else:
      return [ctx.response.get_body()]


main_scope = TheMainClass()

# expose in globals, so we can use @decorator
route = main_scope.route
hook = main_scope.hook
add_route = main_scope.add_route
handle_exception = main_scope.handle_exception


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
    for k, v in merged.items():
      body += '{0:s}: {1:s}'.format(k, v)
    body += '\n'
    body += element.content + '\n'
  body += '--' + marker + '--\n'
  ctx.response.headers[HEADER_CONTENT_TYPE] = 'multipart/{0:s}; boundary={1:s}'.format(mp_type, marker)
  ctx.response.body = body


def static_handler(ctx, filename=None, static_dir='./', mime=None, encoding=None, save_as=None, last=True):
  real_static = os.path.abspath(static_dir)
  real_path = os.path.abspath(os.path.join(static_dir, filename))
  the_logger.debug("Try static file access : {0:s} ".format(real_path))
  if not real_path.startswith(real_static):
    raise Http4xx(http_base.FORBIDDEN)  # 403
  if not os.path.exists(real_path):
    raise Http4xx(http_base.NOT_FOUND)  # 404
  if not os.path.isfile(real_path):
    raise Http4xx(http_base.NOT_FOUND)  # 404
  if not os.access(real_path, os.R_OK):
    raise Http4xx(http_base.FORBIDDEN)  # 403
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
  add_route(url_prefix + "(.*)", target=static_handler, static_dir=static_dir, route_type=ROUTE_CHECK_REGEX)


# expose WSGI handler
application = main_scope.wsgi_handler


def run(server_class=None, **opts):
  the_logger.debug("Preparing WSGI server ... ")
  if server_class is None:
    server_class = WSGIRefServer
  handle = server_class(**opts)
  the_logger.debug("Running server ... ")
  handle.run(application)


if __name__ == '__main__':
  the_logger.warn("Running standalone ?")
  run()

