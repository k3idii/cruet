import json

def plugin_auto_json(mod):
  mod.add_param(do_auto_json = True)

  @mod.hook(mod.HOOK_AFTER)
  def _auto_json_post(ctx):
    if not ctx.do_auto_json:
      return
    if isinstance(ctx.response.body, dict) or isinstance(ctx.response.body, list):
      mod.the_logger.debug('Apply auto JSON (in hook)')
      body = json.dumps(ctx.response.body)
      ctx.response.headers[mod.HEADER_CONTENT_TYPE] = 'application/json'
      ctx.response.body = body


def plugin_auto_head_handler(mod):
  @mod.hook(mod.HOOK_AFTER)
  def _handle_head(ctx):
    if not ctx.request.verb == 'HEAD':
      return
    ctx.response.fix_content_length = False
    ctx.response.headers[mod.HEADER_CONTENT_LENGTH] = len(ctx.response.body)
    ctx.response.body = ''


def plugin_auto_range_handler(mod):
  mod.add_param(do_range = True)

  @mod.hook(mod.HOOK_AFTER)
  def _handle_range_post(ctx):

    def _parse_range(value, max_len=-1):
      # http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.12
      # The only range unit defined by HTTP/1.1 is "bytes".
      range_str_bytes = 'bytes='
      if range_str_bytes not in value:
        raise Exception("Invalid 'range' header syntax !")
      _, value = value.split(range_str_bytes, 1)
      r = []
      for rng in value.split(","):
        if '-' not in rng:
          raise mod.HttpProtocolError("Invalid 'range' header syntax!")
        begin, end = rng.split('-')
        if begin == '' and end == '':
          raise mod.HttpProtocolError("Invalid 'range' header syntax!")
        if begin == '':
          begin = 0
        else:
          begin = int(begin)
        if end == '':
          end = max_len
        else:
          end = int(end)
        if max_len > 0:
          if begin > max_len:
            begin = max_len
          if end > max_len:
            end = max_len
        if end > 0:  # handle -1 as unknown 'end' of data
          if begin > end:
            raise mod.HttpProtocolError("Invalid 'range' header syntax !")
        r.append([begin, end])
      return r

    if not ctx.do_range:
      return
    header_value = ctx.request.headers.get(mod.HEADER_RANGE)
    if not header_value or len(header_value) == 0:
      return
    org_size = len(ctx.response.body)
    ranges = _parse_range(header_value, max_len=org_size)
    if not header_value or len(header_value) == 0:
      return
    ctx.response.set_status(mod.httplib.PARTIAL_CONTENT)  # 206, avoid magic constant ;-)
    if len(ranges) == 1:
      a, b = ranges[0]
      ctx.response.body = ctx.response.body[a:b]
      ctx.response.headers[mod.HEADER_CONTENT_RANGE] = 'bytes {0}-{1}/{2}'.format(a, b, org_size)
      return
    # else len > 1
    parts = []
    for ab in ranges:  # overlapping ranges ? we do not care ;-)
      parts.append(mod.MultipartElement(ctx.response.body[ab[0]:ab[1]]))
    mod.make_multipart(ctx, parts, 'byteranges')
