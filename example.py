import saucepan as sauce


@sauce.route('/hello/<name>', check_method=["GET","POST"])
def handle(ctx, name=None):
  print ctx.request.headers.get('test',None)
  ctx.response.headers.set('test', 'Yes')
  return "Hello <b>{0}</b>".format(name)



def my_route_tester(env):
  return True, 1,2,3

@sauce.route(my_route_tester) # can do check = ROUTER_CHECK_CALL
def handle2(ctx, *args_from_tester):
  return "Handler 2 ",args_from_tester



@sauce.pan.route('/a/b/c', route_type=sauce.ROUTE_CHECK_STR)
def handle3(ctx, *a):
  ctx.response.headers['x-test'] = 1
  return "Handle 3"



def router_generator(ctx):
  print "Hello from generator !"

  def handle4(ctx):
    print "Hello from generated function"
    ctx.response.headers['test'] = ['yes']
    return "Handler from generator !"

  if ctx.request.headers.has('x'):
    return handle4
  return None

sauce.pan.add_route(router_generator, route_type=sauce.ROUTE_GENERATOR)








if __name__ == '__main__':
  sauce.run(host='0.0.0.0', port=12345)
else:
  application = sauce.wsgi_interface()
