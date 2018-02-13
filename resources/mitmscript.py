kiteproxy_mitm_script_content = \
"""
import random
import hashlib
from mitmproxy import ctx
from mitmproxy.script import concurrent
from mitmproxy.proxy.protocol import TlsLayer, RawTCPLayer

white_list = {
    # entertainment
    "cloudfront.net": None,
    "manototv.com": None,
    "9gag.com": None,
    "ggpht.com": None,
    "giphy.com": None,
    # conferences
    "meetupstatic.com": None,
    # upload centers
    "rapidgator.com": None,
    # social networking websites
    "meetup.com": None,
    "reddit.com": None,
    "twitter.com": None,
    "twimg.com": None,
    "t.co": None,
    "youtube.com": None,
    "youtu.be": None,
    "ytimg.com": None,
    "yimg.com": "google.com",
    "googlevideo.com": "google.com",
    "facebook.com": "google.com",
    "facebook.net": "google.com",
    "fbcdn.net": "google.com",
    "flickr.com": None,
    "staticflickr.com": None,
    "vimeocdn.com": None,
    "vimeo.com": None,
    "quora.com": None,
    "pastebin.com": None,
    "disqus.com": None
}

# re-calculate map
global_seed = random.randint(1, 10000)
for key, value in white_list.items():
    hasher = hashlib.md5()
    hasher.update(bytes(key, 'ascii'))
    hasher.update(bytes(str(global_seed), 'ascii'))
    rand = hasher.hexdigest()[:random.randint(3, 8)]
    if value is None:
        value = rand + key
    white_list[key] = value


def _get_target_address(layer):
    try:
        address, port = layer.server_conn.address
        return address
    except:
        return None


def obscure_address(addr):
    host = ".".join(addr.split(".")[-2:])  # r12---sn-qxo7sn7z.googlevideo.com => googlevideo.com
    if host in white_list:
        return addr.replace(host, white_list.get(host))
    else:
        return addr

@concurrent
def next_layer(next_layer):
    if isinstance(next_layer, TlsLayer) and next_layer._client_tls:
        target_address = _get_target_address(next_layer)
        obscured_address = obscure_address(target_address)
        if target_address == obscured_address:
            print("KiteProxy: Passing-through {0}".format(target_address))
            next_layer_replacement = RawTCPLayer(next_layer.ctx, ignore=True)
            next_layer.reply.send(next_layer_replacement)
        else:
            print("KiteProxy: Obscuring host {0} with {1}".format(target_address, obscured_address))
            next_layer.set_server_tls(server_tls=True, sni=obscured_address)         
"""