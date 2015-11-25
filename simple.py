import saucepan as sauce

@sauce.pan.route('/<name>')
def handle_hello(ctx, name=None):
  return "Hello {0:s} !".format(name)

sauce.run(port=8080)
