import logging
logging.basicConfig(level=logging.DEBUG)
import saucepan

@saucepan.route('/<name>')
def handle_hello(ctx, name=None):
  ctx.response.status_message="ACK!"
  return "Hello {0:s} !".format(name)

saucepan.run(port=8081)
