import logging
logging.basicConfig(level=logging.DEBUG)
import saucepan as sauce

@sauce.pan.route('/<name>')
def handle_hello(ctx, name=None):
  ctx.response.status_message="ACK!"
  return "Hello {0:s} !".format(name)

sauce.run(port=8081)
