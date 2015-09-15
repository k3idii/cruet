import cruet as cr

@cr.route('/hello/<name>')
def handle(name):
  return "Hello <b>{0}</b>".format(name)

cr.run(host='0.0.0.0', port=12345)
