from os.path import join, expanduser

user_home = expanduser('~')
kiteproxy_home = join(expanduser('~'), '.kiteproxy')
kiteproxy_cache = join(kiteproxy_home, '.cache')

mitmproxy_ver = '3.0.0_6dd336f'
mitmproxy_url = f'https://github.com/kiteproxy/kiteproxy/releases/download/v1.0-alpha/mitmdump_3.0.0_6dd336fcec6dc32c4986b6c20189bf1b2132153c.zip'

secureoperator_ver = '3.0.0'
secureoperator_url = f'https://github.com/fardog/secureoperator/releases/download/v{secureoperator_ver}/secure-operator_windows-amd64.exe'
secureoperator_host = "127.0.10.53"
secureoperator_google_dns_ips = "74.125.28.100,74.125.28.101,74.125.28.102,74.125.28.113,74.125.28.138,74.125.28.139"

ffaddcert_ver = '1.0.1'
ffaddcert_url = f'https://github.com/christian-korneck/firefox_add-certs/releases/download/{ffaddcert_ver}/firefox_add-certs.zip'

nssm_ver = '2.24'
nssm_url = f'https://nssm.cc/release/nssm-{nssm_ver}.zip'

foxyproxy_ver = '6.1.9'
foxyproxy_url = f'https://addons.mozilla.org/firefox/downloads/file/792104/foxyproxy_standard-{foxyproxy_ver}-an+fx.xpi'
downloaded_foxyproxy_addon = join(kiteproxy_cache, f'foxyproxy-{foxyproxy_ver}.xpi')

firefox_ver = '57.0.4'
firefox_url_generic = 'https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US'
firefox_url = f'https://download-installer.cdn.mozilla.net/pub/firefox/releases/{firefox_ver}/win64/en-US/Firefox%20Setup%20{firefox_ver}.exe'
