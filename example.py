import saucepan
import plugins

plugins.plugin_auto_json(saucepan)
plugins.plugin_auto_range_handler(saucepan)
plugins.plugin_auto_range_handler(saucepan)

GET_POST = saucepan.METHOD_GET + saucepan.METHOD_POST

#     ^- =  list + list

# --------------------------------------------------------------------
# classic add route (like bottle, converted to regex)
@saucepan.route('/hello/<name>', method=GET_POST, custom_hello="Hello")
def handle_simple(ctx, name=None, custom_hello="Hi"):
  """ routing - simple handler w/ helloeter and one custom "static" hello
  """
  print("Hello {0:s}".format(ctx.request.headers.get('test', None)))
  ctx.response.headers['XX-Custom-Header'] = str(name)
  return "{0:s} <b>{1:s}</b>".format(custom_hello, name)


# --------------------------------------------------------------------
# cookie example
@saucepan.route('/cookie')
def handle_cookies(ctx):
  """ Cookie setter/getter
  """
  cookie_name = 'testcookie'
  cookie_value = ctx.cookie(cookie_name)
  rand_string = saucepan.get_random_string(4)
  ctx.cookie(cookie_name, rand_string)
  ctx.cookie('staticname', 'staticvalue')
  return "Cookie [{0}] : current={1} next={2}".format(cookie_name, cookie_value, rand_string)


# --------------------------------------------------------------------
# regex in route
@saucepan.route('/regex/(.)(.)(?P<str1>.*)/abc', route_type=saucepan.ROUTE_CHECK_REGEX)
def handle_re(ctx, c1, c2, str1='none'):
  """ RegEx-based router, catching goups and named groups """
  print("Hello from RE-base route ")
  return "Handling RE route %s|%s|%s !" % (c1, c2, str1)


# --------------------------------------------------------------------
# route tester as callback
def my_route_tester(ctx):
  """ return (true|fals) + arbitray nuber of paramteres that will be passed to handler"""
  if 'function/' in ctx.request.path:
    return True, 'value 1', 'val two'
  return False

@saucepan.route(my_route_tester)  # will auto detect type = ROUTER_CHECK_CALL
def handle_func(ctx, *args_from_tester):
  """ Route dectision by function call (auto-detected), """
  print("Hello from func-based route")
  return "YAY! function returned true ! " + repr(args_from_tester)


# --------------------------------------------------------------------
# full string match (forced by route_type)
@saucepan.route('/str1/str2/str3', route_type=saucepan.ROUTE_CHECK_STR)
def handle_strict(ctx):
  """ strict string check, ad """
  return "string /str1/str2/str3 match !"

# --------------------------------------------------------------------
# return JSON (for API's, etc)
@saucepan.route('/json', route_type=saucepan.ROUTE_CHECK_STR)
def handle_ret_json(ctx):
  """ return JSON """
  return {'this': 'will', "return": "JSON"}


# --------------------------------------------------------------------
# Generator as route
def router_generator(ctx):
  """ generator based routing """
  def handle_generator(local_ctx):
    print("Hello from generated function")
    local_ctx.response.headers['test'] = ['yes']
    return "Handler from generator !"

  print("Hello from generator-based router !")
  if "generator" in ctx.request.path or ctx.request.headers.has('generator'):
    return handle4
  return None

saucepan.add_route(router_generator, route_type=saucepan.ROUTE_GENERATOR)

# --------------------------------------------------------------------
# guess what ^_^
saucepan.register_static_file_handler(url_prefix='/static/')


# --------------------------------------------------------------------
# multipart answer >
@saucepan.route("/multipart")
def do_multipart(ctx):
  """ content-type:Multipart response """
  parts = [saucepan.MultipartElement('test123'), saucepan.MultipartElement('test123')]
  return saucepan.make_multipart(ctx, parts)


# --------------------------------------------------------------------
# can do 302 by raising exception ;-)
@saucepan.route("/redirect")
def do_302(ctx):
  """ 302 response code by exception """
  raise saucepan.Http3xx(302, target="/destination")

@saucepan.route("/destination")
def do_dst(ctx):
  return 'Landed !'

@saucepan.route("/404")
def do_404(ctx):
  """ 404 response by exception """
  raise saucepan.Http4xx(404)

# --------------------------------------------------------------------
# route that raise Exception ...
@saucepan.route("/crash")
def crash_it(ctx):
  print("Will raise generic Exception if 1+1 == 2 ! ")
  if 1 + 1 == 2:
    raise Exception("Not real exception ...")
  return "OK"

# --------------------------------------------------------------------
# file upload demo
@saucepan.route("/upload")
def upl_route(ctx):
  # print ctx.request.headers._env
  return "OK"


# --------------------------------------------------------------------
# full string match (forced by route_type)
@saucepan.route('/form', route_type=saucepan.ROUTE_CHECK_STR)
def handle3(ctx):
  # for k,v in ctx.request.headers._env.iteritems():
  #  print `k`,`v`
  s = '\n\n'.join([
    'GET:{0}'.format(repr(ctx.request.get)),
    'POST:{0}'.format(repr(ctx.request.post)),
    'FILES:{0}'.format(repr(ctx.request.files)),
    'COOKIE:{0}'.format(repr(ctx.request.cookies)),
    'HEADERS:{0}'.format(str(ctx.request.headers))
  ])
  return """<pre>{0:s}</pre><hr>""".format(s) + """
  <form method="GET" action="?"><input name="f1" value="x1"><input type="submit"></form>
  <hr>
  <form method="POST" action="?"><input name="f1" value="x1"><input type="submit"></form>
  <hr>
  <form method="POST" action="?" enctype="multipart/form-data"><input name="mp1" value="x1">
  <input type="file" name="f1" /><input type="file" name="f2" /><input type="submit"></form>
  """


# --------------------------------------------------------------------
# class wrapper, manditory argument: method name
@saucepan.route("/funcs/<method>")
class FuncsHandler(saucepan.RoutableClass):
  """ class-based handler, assume 1st arg == method """
  def default(self, ctx):
    return "You call bad func !"
  
  def do_test(self, ctx):
    return "Hai, I'm method !"


# --------------------------------------------------------------------
# default route (ROUTE_ALWAYS == 'None' == always match)
@saucepan.route(saucepan.ROUTE_ALWAYS)
def default_route(ctx):
  return "Hello. This is default handler !"


# --------------------------------------------------------------------
# register exception handler (like route ^_^)
@saucepan.handle_exception(Exception)
def handle_exception1(ctx, err):
  """ register exception handler for specific class of exception """
  print("Exception handler HIT !! {0} / {1}: ".format(str(ctx),err))
  import traceback
  import sys
  info = sys.exc_info()
  traceback.print_exception(*info)  # <- send logs to admin ;-)
  return "Exception handled, do not panic !!!"

# --------------------------------------------------------------------
#

@saucepan.hook(saucepan.HOOK_BEFORE, arg=2)
def post_hook_1(ctx, arg):
  """ hook executed before handler (i.e. preauth) """
  print("HTTP Host == {0:s}".format(ctx.request.heders['Host']))


@saucepan.hook(saucepan.HOOK_AFTER, arg=2)
def post_hook_1(ctx, arg):
  """ hook executed after handler """
  print("Hook executed after handler")
  ctx.response.headers['x-hooked-value'] = arg



if __name__ == '__main__':
  saucepan.run(host='0.0.0.0', port=12345)
else:
  application = saucepan.application
