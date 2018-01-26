kiteproxy_mitm_script_content = \
"""
from mitmproxy import ctx
from mitmproxy.script import concurrent
from mitmproxy.proxy.protocol import TlsLayer, RawTCPLayer

white_list = {
# entertainment    
    "9gag.com",
    "ggpht.com",
    "giphy.com",
    "phncdn.com",
# conferences    
    "meetup.com",
    "meetupstatic.com",
# upload centers
    "rapidgator.com",
    "torproject.org",
# social networking websites
    "meetup.com",
    "reddit.com",
    "twitter.com",
    "twimg.com",
    "t.co",
    "youtube.com",
    "youtu.be",
    "ytimg.com",
    "yimg.com",
    "googlevideo.com",
    "facebook.com",
    "facebook.net",
    "fbcdn.net",
    "flickr.com",
    "staticflickr.com",
    "vimeocdn.com",
    "vimeo.com",
    "quora.com",
    "pastebin.com",
    "disqus.com"
}


def _get_target_address(layer):
    try:
        address, port = layer.server_conn.address
        return address
    except:
        return None


def obscure_address(addr):
    host = ".".join(addr.split(".")[-2:])  # r12---sn-qxo7sn7z.googlevideo.com => googlevideo.com
    if host in white_list:
        return addr.replace(host, "xxx" + host)
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