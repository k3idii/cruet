import logging
logging.basicConfig(level=logging.DEBUG)

import saucepan as sauce

# --------------------------------------------------------------------
# classic add route (like bottle, converted to regex)
@sauce.route('/hello/<name>', check_method=["GET","POST"], custom_param="Hello")
def handle(ctx, name=None, custom_param="<missing>"):
  print ctx.request.headers.get('test',None)
  ctx.response.headers['test']='Yes'
  return "{0:s} <b>{1:s}</b>".format(custom_param, name)

# --------------------------------------------------------------------
# regex in route
@sauce.route('/bye/(.)(.)(?P<str1>.*)/bye', route_type=sauce.ROUTE_CHECK_REGEX)
def handle_re(ctx, c1, c2, str1='none'):
  print "Hello from re-base route "
  return "HANDLE RE %s|%s|%s !" % (c1, c2, str1)

# --------------------------------------------------------------------
#route tester as callback
def my_route_tester(ctx):
  if 'test2' in ctx.request.path:
    return True, 'value 1', 'val two'
  return False

@sauce.route(my_route_tester) # will auto detect type = ROUTER_CHECK_CALL
def handle2(ctx, *args_from_tester):
  print "Hello from handle2"
  return "Handler 2 " + `args_from_tester`

# --------------------------------------------------------------------
# full string match (forced by route_type)
@sauce.pan.route('/a/b/c', route_type=sauce.ROUTE_CHECK_STR)
def handle3(ctx, *a):
  ctx.response.headers['x-test'] = 1
  return "Handle 3, match /a/b/c"

# --------------------------------------------------------------------
# Generator as route
def router_generator(ctx):
  print ">> Generator is trying to run ..."

  def handle4(ctx):
    print "Hello from generated function"
    ctx.response.headers['test'] = ['yes']
    return "Handler from generator !"

  if ctx.request.headers.has('xxx'):
    return handle4
  return None

sauce.pan.add_route(router_generator, route_type=sauce.ROUTE_GENERATOR)
# ^--- also can to this using @decorator ;-)


# --------------------------------------------------------------------
# route that raise Exception ...
@sauce.pan.route("/crash")
def crash_it(ctx):
  if 1+1 == 2:
    raise Exception("Not real exception ...")
  return "OK"


# --------------------------------------------------------------------
# default route (none == always match)
@sauce.pan.route(None)
def default_route(ctx):
  return "Hello. This is default handler !"


# --------------------------------------------------------------------
# register exception handler (like route ^_^)
@sauce.pan.handle_exception(Exception)
def handle_exception1(ctx,err):
  print "Exception handler : ",ctx, err
  return "Exception handled, do not panic !!!"

if __name__ == '__main__':
  sauce.run(host='0.0.0.0', port=12345)
else:
  application = sauce.wsgi_interface()
