import logging

logging.basicConfig(level=logging.DEBUG)

import saucepan as sauce

# <- enable additional processing
sauce.enable_auto_json()
sauce.enable_auto_head_handler()
sauce.enable_auto_range_handler()


GET_POST = sauce.METHOD_GET + sauce.METHOD_POST
#     ^- =  list + list

# --------------------------------------------------------------------
# classic add route (like bottle, converted to regex)
@sauce.route('/hello/<name>', method=GET_POST, custom_param="Hello")
def handle(ctx, name=None, custom_param="Hi"):
  print ctx.request.headers.get('test', None)
  ctx.response.headers['test'] = 'Yes'
  return "{0:s} <b>{1:s}</b>".format(custom_param, name)


# --------------------------------------------------------------------
# regex in route
@sauce.route('/bye/(.)(.)(?P<str1>.*)/bye', route_type=sauce.ROUTE_CHECK_REGEX)
def handle_re(ctx, c1, c2, str1='none'):
  print "Hello from re-base route "
  return "HANDLE RE %s|%s|%s !" % (c1, c2, str1)


# --------------------------------------------------------------------
# route tester as callback
def my_route_tester(ctx):
  if 'test2' in ctx.request.path:
    return True, 'value 1', 'val two'
  return False


@sauce.route(my_route_tester)  # will auto detect type = ROUTER_CHECK_CALL
def handle2(ctx, *args_from_tester):
  print "Hello from handle2"
  return "Handler 2 " + repr(args_from_tester)


# --------------------------------------------------------------------
# full string match (forced by route_type)
@sauce.pan.route('/a/b/c', route_type=sauce.ROUTE_CHECK_STR)
def handle3(ctx):
  ctx.response.headers['x-test'] = 1
  return {'this': 'will', "return": "JSON"}


# --------------------------------------------------------------------
# Generator as route
def router_generator(ctx):

  def handle4(local_ctx):
    print "Hello from generated function"
    local_ctx.response.headers['test'] = ['yes']
    return "Handler from generator !"

  if ctx.request.headers.has('xxx'):
    return handle4
  return None


sauce.pan.add_route(router_generator, route_type=sauce.ROUTE_GENERATOR)
# ^--- also can to this using @decorator ;-)


# --------------------------------------------------------------------
# guess what ^_^
sauce.register_static_file_handler(url_prefix='/static/')


# --------------------------------------------------------------------
# multipart answer >
@sauce.pan.route("/multipart")
def do_multipart(ctx):
  parts = []
  parts.append(sauce.MultipartElement('test123'))
  parts.append(sauce.MultipartElement('test123'))
  return sauce.make_multipart(ctx, parts)


# --------------------------------------------------------------------
# can do 302 by raising exception ;-)
@sauce.pan.route("/redirect")
def do_302(ctx):
  raise sauce.Http3xx("/destination")


@sauce.pan.route("/destination")
def do_dst(ctx):
  return 'Landed !'


# --------------------------------------------------------------------
# route that raise Exception ...
@sauce.pan.route("/crash")
def crash_it(ctx):
  if 1 + 1 == 2:
    raise Exception("Not real exception ...")
  return "OK"


# --------------------------------------------------------------------
# file upload demo
@sauce.pan.route("/upload")
def upl_route(ctx):
  print ctx.request.headers._env
  return "OK"

# --------------------------------------------------------------------
# full string match (forced by route_type)
@sauce.pan.route('/form', route_type=sauce.ROUTE_CHECK_STR)
def handle3(ctx):
  #for k,v in ctx.request.headers._env.iteritems():
  #  print `k`,`v`
  s = ''
  s += 'GET:{0}'.format(repr(ctx.request.get))
  s += '\n\n'
  s += 'POST:{0}'.format(repr(ctx.request.post))
  s += '\n\n'
  s += 'COOKIE:{0}'.format(repr(ctx.request.cookies))
  s += '\n\n'
  s += 'HEADERS:{0}'.format(str(ctx.request.headers))

  return """<pre>{0:s}</pre><hr>
  <form method="GET" action="?">
  <input name="f1" value="x1"><input type="submit">
  </form>
  <hr>
  <form method="POST" action="?">
  <input name="f1" value="x1"><input type="submit">
  </form>
  <hr>
  <form method="POST" action="?" enctype="multipart/form-data">
  <input name="f1" value="x1">
  <input type="file" name="file" />
  <input type="submit">
  </form>
  """.format(s)


# --------------------------------------------------------------------
# default route (ROUTE_ALWAYS == None == always match)
@sauce.pan.route(sauce.ROUTE_ALWAYS)
def default_route(ctx):
  return "Hello. This is default handler !"


# --------------------------------------------------------------------
# register exception handler (like route ^_^)
@sauce.pan.handle_exception(Exception)
def handle_exception1(ctx, err):
  print "Exception handler HIT !! : ", ctx, err
  import traceback
  import sys

  info = sys.exc_info()
  traceback.print_exception(*info)  # <- send logs to admin ;-)
  return "Exception handled, do not panic !!!"


# --------------------------------------------------------------------
# register exception handler (like route ^_^)
@sauce.pan.hook(sauce.HOOK_POST, a=2)
def post_hook_1(ctx, a):
  ctx.response.headers['x-hooked'] = a


if __name__ == '__main__':
  sauce.run(host='0.0.0.0', port=12345)
else:
  application = sauce.wsgi_interface()
