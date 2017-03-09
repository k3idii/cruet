import logging
import json


def plugin_auto_json(m):
  @m.hook(m.HOOK_BEFORE)
  def _auto_json_pre(ctx):
    ctx.do_auto_json = True

  @m.hook(m.HOOK_AFTER)
  def _auto_json_post(ctx):
    if not ctx.do_auto_json:
      return
    if isinstance(ctx.response.body, dict) or isinstance(ctx.response.body, list):
      logging.debug('Apply auto JSON (in hook)')
      body = json.dumps(ctx.response.body)
      ctx.response.headers[m.HEADER_CONTENT_TYPE] = 'application/json'
      ctx.response.body = body


def plugin_auto_head_handler(m):
  @m.hook(m.HOOK_AFTER)
  def _handle_head(ctx):
    if not ctx.request.verb == 'HEAD':
      return
    ctx.response.fix_content_length = False
    ctx.response.headers[m.HEADER_CONTENT_LENGTH] = len(ctx.response.body)
    ctx.response.body = ''


def plugin_auto_range_handler(m):
  @m.hook(m.HOOK_BEFORE)
  def _handle_range_pre(ctx):
    ctx.do_range = True

  @m.hook(m.HOOK_AFTER)
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
          raise m.HttpProtocolError("Invalid 'range' header syntax!")
        a, b = rng.split('-')
        if a == '' and b == '':
          raise m.HttpProtocolError("Invalid 'range' header syntax!")
        if a == '':
          a = 0
        else:
          a = int(a)
        if b == '':
          b = max_len
        else:
          b = int(b)
        if max_len > 0:
          if a > max_len:
            a = max_len
          if b > max_len:
            b = max_len
        if b > 0:  # handle -1 as unknown 'end' of data
          if a > b:
            raise m.HttpProtocolError("Invalid 'range' header syntax !")
        r.append([a, b])
      return r

    if not ctx.do_range:
      return
    header_value = ctx.request.headers.get(m.HEADER_RANGE)
    if not header_value or len(header_value) == 0:
      return
    org_size = len(ctx.response.body)
    ranges = _parse_range(header_value, max_len=org_size)
    if not header_value or len(header_value) == 0:
      return
    ctx.response.set_status(m.httplib.PARTIAL_CONTENT)  # 206, avoid magic constant ;-)
    if len(ranges) == 1:
      a, b = ranges[0]
      ctx.response.body = ctx.response.body[a:b]
      ctx.response.headers[m.HEADER_CONTENT_RANGE] = 'bytes {0}-{1}/{2}'.format(a, b, org_size)
      return
    # else len > 1
    parts = []
    for ab in ranges:  # overlapping ranges ? we do not care ;-)
      parts.append(m.MultipartElement(ctx.response.body[ab[0]:ab[1]]))
    m.make_multipart(ctx, parts, 'byteranges')
