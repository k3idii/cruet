import cruet as cr


@cr.route('/hello/<name>')
def handle(name):
  return "Hello <b>{0}</b>".format(name)


def my_route_tester(env):
  return True

@cr.route(my_route_tester)
def handle2(*a):
  return "Handler 2 "

cr.add_route('test', handle2)


cr.run(host='0.0.0.0', port=12345)
