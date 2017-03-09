import logging

logging.basicConfig(level=logging.DEBUG)

import saucepan
import plugins

plugins.plugin_auto_json(saucepan)
plugins.plugin_auto_range_handler(saucepan)
plugins.plugin_auto_range_handler(saucepan)

GET_POST = saucepan.METHOD_GET + saucepan.METHOD_POST
#     ^- =  list + list

# --------------------------------------------------------------------
# classic add route (like bottle, converted to regex)
@saucepan.route('/hello/<name>', method=GET_POST, custom_param="Hello")
def handle(ctx, name=None, custom_param="Hi"):
  print ctx.request.headers.get('test', None)
  ctx.response.headers['test'] = 'Yes'
  return "{0:s} <b>{1:s}</b>".format(custom_param, name)


# --------------------------------------------------------------------
# cookie example
@saucepan.route('/cookie')
def handle_cookies(ctx):
  cn = 'xxx'
  cc = ctx.cookie(cn)
  nn = saucepan.get_random_string(4)
  ctx.cookie(cn, nn)
  ctx.cookie('static', 'value')
  return "Cookie [{0}] : current={1} next={2}".format(cn, cc, nn)


# --------------------------------------------------------------------
# regex in route
@saucepan.route('/bye/(.)(.)(?P<str1>.*)/bye', route_type=saucepan.ROUTE_CHECK_REGEX)
def handle_re(ctx, c1, c2, str1='none'):
  print "Hello from re-base route "
  return "HANDLE RE %s|%s|%s !" % (c1, c2, str1)


# --------------------------------------------------------------------
# route tester as callback
def my_route_tester(ctx):
  if 'test2' in ctx.request.path:
    return True, 'value 1', 'val two'
  return False


@saucepan.route(my_route_tester)  # will auto detect type = ROUTER_CHECK_CALL
def handle2(ctx, *args_from_tester):
  print "Hello from handle2"
  return "Handler 2 " + repr(args_from_tester)


# --------------------------------------------------------------------
# full string match (forced by route_type)
@saucepan.route('/a/b/c', route_type=saucepan.ROUTE_CHECK_STR)
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


saucepan.add_route(router_generator, route_type=saucepan.ROUTE_GENERATOR)
# ^--- also can to this using @decorator ;-)


# --------------------------------------------------------------------
# guess what ^_^
saucepan.register_static_file_handler(url_prefix='/static/')


# --------------------------------------------------------------------
# cookie example
@saucepan.route('/cookie')
def handle_cookies(ctx):
  cn = 'xxx'
  cc = ctx.cookie(cn)
  nn = saucepan.get_random_string(4)
  ctx.cookie(cn, nn)
  ctx.cookie('static', 'value')
  return "Cookie [{0}] : current={1} next={2}".format(cn, cc, nn)


# --------------------------------------------------------------------
# multipart answer >
@saucepan.route("/multipart")
def do_multipart(ctx):
  parts = [saucepan.MultipartElement('test123'), saucepan.MultipartElement('test123')]
  return saucepan.make_multipart(ctx, parts)


# --------------------------------------------------------------------
# can do 302 by raising exception ;-)
@saucepan.route("/redirect")
def do_302(ctx):
  raise saucepan.Http3xx(302, target="/destination")

@saucepan.route("/404")
def do_404(ctx):
  raise saucepan.Http4xx(404)

@saucepan.route("/destination")
def do_dst(ctx):
  return 'Landed !'


# --------------------------------------------------------------------
# route that raise Exception ...
@saucepan.route("/crash")
def crash_it(ctx):
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
# default route (ROUTE_ALWAYS == None == always match)
@saucepan.route("/funcs/<method>")
class FuncsHandler(saucepan.RoutableClass):
  def do_test(self, ctx):
    return "Hai, I'm method !"


# --------------------------------------------------------------------
# default route (ROUTE_ALWAYS == None == always match)
@saucepan.route(saucepan.ROUTE_ALWAYS)
def default_route(ctx):
  return "Hello. This is default handler !"


# --------------------------------------------------------------------
# register exception handler (like route ^_^)
@saucepan.handle_exception(Exception)
def handle_exception1(ctx, err):
  print "Exception handler HIT !! : ", ctx, err
  import traceback
  import sys

  info = sys.exc_info()
  traceback.print_exception(*info)  # <- send logs to admin ;-)
  return "Exception handled, do not panic !!!"


# --------------------------------------------------------------------
#
@saucepan.hook(saucepan.HOOK_AFTER, arg=2)
def post_hook_1(ctx, arg):
  ctx.response.headers['x-hooked-value'] = arg


if __name__ == '__main__':
  saucepan.run(host='0.0.0.0', port=12345)
else:
  application = saucepan.application
