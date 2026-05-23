"""WhatIsMyIP by Al Sweigart al@inventwithpython.com

Fetch your public IP address from external sources.

Example:
    >>> import whatismyip
    >>> whatismyip.amionline()
    True
    >>> whatismyip.whatismyip()
    '69.89.31.226'
    >>> whatismyip.whatismyipv4()
    '69.89.31.226'
    >>> whatismyip.whatismyipv6()
    '2345:0425:2CA1:0000:0000:0567:5673:23b5'
    >>> whatismyip.whatismylocalip()  # Returns local IPs of all network cards.
    ('192.168.189.1', '192.168.220.1', '192.168.56.1', '192.168.1.201')
    >>> whatismyip.whatismyhostname()
    'GIBSON'
"""

__version__ = '2026.5.22'

import logging
import random
import re
import socket
import time
import urllib.request

from typing import Optional, Pattern, Tuple, Sequence

_log = logging.getLogger(__name__)

# Repeated calls to whatismyip()/whatismyipv4()/whatismyipv6() with default
# arguments will reuse a result that was fetched less than this many seconds
# ago. Short enough that a DHCP renewal or VPN connect is picked up quickly,
# long enough to spare polling scripts from hammering STUN servers. Callers
# that pass an explicit `sources=` argument always bypass the cache.
_CACHE_TTL_SECONDS = 10
_ip_cache = {}  # type: dict  # key (str) -> (expiry_monotonic, value)


def _cache_get(key):
    # type: (str) -> Optional[str]
    entry = _ip_cache.get(key)
    if entry is None:
        return None
    expiry, value = entry
    if time.monotonic() >= expiry:
        return None
    return value


def _cache_set(key, value):
    # type: (str, str) -> None
    _ip_cache[key] = (time.monotonic() + _CACHE_TTL_SECONDS, value)


def _clear_cache():
    # type: () -> None
    """Discard any cached IP address results so the next call refetches.
    Useful in tests or after a known network change (VPN toggle, etc.)."""
    _ip_cache.clear()

# Adapted from https://stackoverflow.com/a/5284410/1893164
# Use with .fullmatch() — the regex itself only describes a well-formed IPv4 string.
_IPV4_OCTET = r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
IPV4_REGEX = re.compile(r"(" + _IPV4_OCTET + r"\.){3}" + _IPV4_OCTET)  # type: Pattern

# From https://stackoverflow.com/a/17871737/1893164
IPV6_REGEX = re.compile(
    r"""(
([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|          # 1:2:3:4:5:6:7:8
([0-9a-fA-F]{1,4}:){1,7}:|                         # 1::                              1:2:3:4:5:6:7::
([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|         # 1::8             1:2:3:4:5:6::8  1:2:3:4:5:6::8
([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|  # 1::7:8           1:2:3:4:5::7:8  1:2:3:4:5::8
([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|  # 1::6:7:8         1:2:3:4::6:7:8  1:2:3:4::8
([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|  # 1::5:6:7:8       1:2:3::5:6:7:8  1:2:3::8
([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|  # 1::4:5:6:7:8     1:2::4:5:6:7:8  1:2::8
[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|       # 1::3:4:5:6:7:8   1::3:4:5:6:7:8  1::8
:((:[0-9a-fA-F]{1,4}){1,7}|:)|                     # ::2:3:4:5:6:7:8  ::2:3:4:5:6:7:8 ::8       ::
fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|     # fe80::7:8%eth0   fe80::7:8%1     (link-local IPv6 addresses with zone index)
::(ffff(:0{1,4}){0,1}:){0,1}
((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}
(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|          # ::255.255.255.255   ::ffff:255.255.255.255  ::ffff:0:255.255.255.255  (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
([0-9a-fA-F]{1,4}:){1,4}:
((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}
(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])           # 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
)""",
    re.VERBOSE,
)  # type: Pattern


# If you have an IPv4 *and* IPv6 address, these websites give you your IPv4 address.
# (I haven't tested what they do if you only have an IPv6 address.)
# Ordered by response time (fastest first). Re-test by running _profile_https_servers().
# Last re-profiled: 2026-05-22 from Brooklyn, NY, USA.
IP4_WEBSITES = ('https://api.ipify.org',
                'https://checkip.amazonaws.com/',
                'https://ipecho.net/plain',
                'https://ifconfig.me/ip',
                'https://ipinfo.io/ip',
                'https://v4.tnedi.me',
                'https://v4.ident.me',
                # Removed 2026-05-22:
                # 'https://ifconfig.co/ip' — now behind a Cloudflare JS challenge (returns 403).
                # 'https://ipaddr.site'   — TLS certificate expired.
                )

# Note: In the event that your system only has an IPv4 address and no IPv6 address,
# these websites will return your IPv4 address.
# Ordered by response time (fastest first). Last re-profiled: 2026-05-22.
IP6_WEBSITES = ('https://icanhazip.com',
                'https://wtfismyip.com/text',
                'https://curlmyip.net',
                'https://v6.ident.me',
                'https://tnedi.me/',
                'https://v6.tnedi.me',
                # 'https://ip.seeip.org' — service offline as of 2026-05-22.
                )

IP_WEBSITES = IP4_WEBSITES + IP6_WEBSITES

# TODO - add other websites that provide this info in a web page, along with a regex that can pull out the IP address.
# Example: http://checkip.dyndns.org

# Popular web servers to test if we are online. (2024/02/20 - youtube.com was removed since it is blocked in some countries)
ONLINE_WEB_SERVERS = ('google.com', 'facebook.com', 'yahoo.com', 'reddit.com', 'wikipedia.org', 'ebay.com', 'bing.com', 'netflix.com', 'office.com', 'twitch.tv', 'cnn.com', 'linkedin.com')


# Responsive servers that responded in less than 0.3 seconds, in order of fastest response time. Re-test their speeds by calling _profile_stun_servers().
# Last re-profiled: 2026-05-22 from Brooklyn, NY, USA. 77 servers (down from 85 in 2024-02-20 — see git log for the previous lists).
STUN_SERVERS = ('stun.l.google.com:19302', 'stun.l.google.com:3478', 'stun2.l.google.com:19302', 'stun3.l.google.com:19302', 'stun1.l.google.com:19302', 'stun4.l.google.com:19302', 'stun.usfamily.net:3478', 'stun.epygi.com:3478', 'stun.voip.aebc.com:3478', 'stun.voipzoom.com:3478', 'stun.voys.nl:3478', 'stun.lowratevoip.com:3478', 'stun.voicetrading.com:3478', 'stun.voippro.com:3478', 'stun.freeswitch.org:3478', 'stun.aeta-audio.com:3478', 'stun.voipbuster.com:3478', 'stun.internetcalls.com:3478', 'stun.actionvoip.com:3478', 'stun.acrobits.cz:3478', 'stun.linphone.org:3478', 'stun.sipgate.net:10000', 'stun.voip.blackberry.com:3478', 'stun.cheapvoip.com:3478', 'stun.easyvoip.com:3478', 'stun.siptraffic.com:3478', 'stun.12voip.com:3478', 'stun.voipstunt.com:3478', 'stun.myvoiptraffic.com:3478', 'stun.telbo.com:3478', 'stun.voipgate.com:3478', 'stun.poivy.com:3478', 'stun.netappel.com:3478', 'stun.voipwise.com:3478', 'stun.twt.it:3478', 'stun.siplogin.de:3478', 'stun.rynga.com:3478', 'stun.justvoip.com:3478', 'stun.ippi.fr:3478', 'stun.freevoipdeal.com:3478', 'stun.voipblast.com:3478', 'stun.voip.eutelia.it:3478', 'stun.voipraider.com:3478', 'stun.powervoip.com:3478', 'stun.voipgain.com:3478', 'stun.jumblo.com:3478', 'stun.voipcheap.com:3478', 'stun.schlund.de:3478', 'stun.nonoh.net:3478', 'stun.freecall.com:3478', 'stun.smartvoip.com:3478', 'stun.nextcloud.com:443', 'stun.voipbusterpro.com:3478', 'stun.intervoip.com:3478', 'stun.callromania.ro:3478', 'stun.gmx.net:3478', 'stun.zoiper.com:3478', 'stun.1und1.de:3478', 'stun.voipinfocenter.com:3478', 'stun.webcalldirect.com:3478', 'stun.cablenet-as.net:3478', 'stun.solnet.ch:3478', 'stun.zadarma.com:3478', 'stun.ppdi.com:3478', 'stun.cope.es:3478', 'stun.halonet.pl:3478', 'stun.annatel.net:3478', 'stun.t-online.de:3478', 'stun.liveo.fr:3478', 'stun.voztele.com:3478', 'stun.mywatson.it:3478', 'stun.dcalling.de:3478', 'stun.aeta.com:3478', 'stun.hoiio.com:3478', 'stun.gmx.de:3478', 'stun.dus.net:3478', 'stun.it1.hr:3478', 'stun.uls.co.za:3478')


# STUN attribute types (RFC 5389 §15):
MAPPED_ADDRESS = b'\x00\x01'
STUN_ATTR_LEN = 4  # bytes of header per attribute (type + length)

# STUN message types (RFC 5389 §6):
BIND_REQUEST_MSG = b'\x00\x01'
BIND_RESPONSE_MSG = b'\x01\x01'

# Note: Because this module is named whatismyip and it's a small module that likely people will only use for its
# whatismyip() function, I've kept the all-lowercase, no-underscore naming convention for the public functions.
# It would be too confusing to have whatismyip.what_is_my_ip(). Please don't complain about pep8 to me.

def whatismyip(sources=None):
    # type: (Optional[Sequence[str]]) -> Optional[str]
    """Returns a str of your IP address, either IPv4 or IPv6, or None if offline
    or the IP address can't be determined.

    :param sources: Optional sequence of HTTPS endpoints that return an IP
        address (similar to the entries in IP_WEBSITES). When provided, STUN
        is skipped and only these endpoints are consulted, and the result
        is not cached.
    :type sources: sequence of str, or None.
    """
    if sources is not None:
        return _get_ip_from_https(web_servers=sources)

    cached = _cache_get('any')
    if cached is not None:
        return cached

    # Get ipv4 address from STUN servers first (they tend to be faster than the websites):
    # Note: STUN servers only return IPv4 addresses. This means that whatismyip() will almost
    # always return the IPv4 address of users who have both IPv4 and IPv6 addresses.
    # (TODO: Test this claim.)
    for i in range(3):  # Make 3 attempts, otherwise assume accessing STUN is blocked for some reason.
        ip = _get_ip_from_stun()  # Check a random STUN server.
        if ip is not None:
            _cache_set('any', ip)
            return ip

    ip = _get_ip_from_https()
    if ip is not None:
        _cache_set('any', ip)
    return ip


def whatismyipv4():
    # type: () -> Optional[str]
    """Returns a str of your IPv4 address. If offline or the IP address can't
    be determined, this returns None."""

    cached = _cache_get('v4')
    if cached is not None:
        return cached

    # Get ipv4 address from STUN servers first (they tend to be faster than the websites):
    # Note: STUN servers only return IPv4 addresses. (TODO: Test this claim.)
    for i in range(3):  # Make 3 attempts, otherwise assume accessing STUN is blocked for some reason.
        ip = _get_ip_from_stun()  # Check a random STUN server.
        if ip is not None:
            _cache_set('v4', ip)
            return ip

    ip = _get_ip_from_https(4)
    if ip is not None:
        _cache_set('v4', ip)
    return ip


def whatismyipv6():
    # type: () -> Optional[str]
    """Returns a str of your IPv6 address, or None if offline or you don't have an IPv6 address."""
    cached = _cache_get('v6')
    if cached is not None:
        return cached
    ip = _get_ip_from_https(6)
    if ip is not None:
        _cache_set('v6', ip)
    return ip


def whatismylocalip():
    # type: () -> Tuple[str, ...]
    """Returns a tuple of local IP address strings — one entry per network
    interface on the machine. These are LAN addresses (e.g. 192.168.x.x),
    not the public IP returned by `whatismyip()`. Returns an empty tuple
    if the local hostname can't be resolved (a common quirk on freshly
    configured macOS machines)."""
    try:
        return tuple(socket.gethostbyname_ex(socket.gethostname())[2])
    except socket.gaierror as exc:
        _log.debug('whatismylocalip: hostname resolution failed: %r', exc)
        return ()


def whatismyhostname():
    # type: () -> str
    return socket.gethostname()


def _cli():
    # type: () -> int
    """Entry point used by both `python -m whatismyip` and the
    `whatismyip` console script. Prints the IP (if available) and
    returns an exit code: 0 on success, 1 if no IP could be determined."""
    ip = whatismyip()
    if ip is None:
        import sys
        print('Could not determine your IP address.', file=sys.stderr)
        return 1
    print(ip)
    return 0


def amionline(web_servers=None):
    # type: (Optional[Sequence[str]]) -> bool
    """Return True if the system is currently on the internet, otherwise returns False.

    It determines this by attempting to connect to a popular web server in the `ONLINE_WEB_SERVERS` list.

    :param web_servers: A list of web server domain names to check for connectivity (or `ONLINE_WEB_SERVERS` if
        None), defaults to None.
    :type web_servers: list, optional
    :return: True if the system is online, False if not online.
    :rtype: bool
    """
    # If web_servers is not provided, use the default list of popular web servers.
    if web_servers is None:
        web_servers = list(ONLINE_WEB_SERVERS)
    else:
        web_servers = list(web_servers)

    # Shuffle the list of web servers to try a random sequence.
    random.shuffle(web_servers)

    # Try to connect to up to 3 randomly selected web servers.
    for server in web_servers[:3]:
        try:
            socket.getaddrinfo(server, 'www')
            return True
        except socket.gaierror:
            continue

    # If all attempts have failed (or web_servers was empty), the system is offline.
    return False

# Note: Private functions will use snake_case.

def _get_ip_from_https(ip_version=None, web_servers=None):
    # type: (Optional[int], Optional[Sequence[str]]) -> Optional[str]
    """Returns a str of your IPv4 or IPv6 address from a "whatismyip" website.
    If offline or the IP address can't be determined, this returns None.

    :param ip_version: The IP address version you want: either 4, 6, or None
    for either.
    :type ip_version: The ints 4 or 6, or None.
    :param web_servers: Optional sequence of websites that return an IP address,
    similar to the ones in IP_WEBSITES."""

    if web_servers is None:
        # By default, we keep checking each website in IP_WEBSITES until
        # we get a valid response.
        ipWebsites = list(IP_WEBSITES)
    else:
        ipWebsites = list(web_servers)
    random.shuffle(ipWebsites)

    for ipWebsite in ipWebsites:  # Go through all ip website servers, return the first valid response.
        try:
            response = urllib.request.urlopen(ipWebsite, timeout=5)

            charsets = response.info().get_charsets()
            if len(charsets) == 0 or charsets[0] is None:
                charset = 'utf-8'  # Use utf-8 by default
            else:
                charset = charsets[0]

            userIp = response.read().decode(charset).strip()

            if ip_version == 4 and IPV4_REGEX.fullmatch(userIp):
                return userIp
            elif ip_version == 6 and IPV6_REGEX.fullmatch(userIp):
                return userIp
            elif ip_version is None and (IPV4_REGEX.fullmatch(userIp) or IPV6_REGEX.fullmatch(userIp)):
                return userIp
            else:
                # Either the ip_version argument is invalid or the ip website
                # returned some unexpected text that is not an IP address.
                # (Or the user asked for, say, ipv4 and got an ipv6 address.)
                _log.debug('Unexpected response from %s: %r', ipWebsite, userIp)
                continue
        except Exception as exc:
            _log.debug('Failed to fetch IP from %s: %r', ipWebsite, exc)

    # Either all of the websites are down or returned invalid response
    # (unlikely) or you are disconnected from the internet (likely).
    return None


def _get_ip_from_stun(stun_servers=None):
    # type: (Optional[Sequence[str]]) -> Optional[str]
    """Retrieves the IPv4 address from a STUN (Session Traversal Utilities for
    NAT) server. If `stun_servers` isn't specified, a public STUN server is
    randomly selected from the STUN_SERVERS tuple. Each entry must be a
    `'host:port'` string."""
    SOURCE_IP = '0.0.0.0'
    SOURCE_PORT = 0  # 0 means the OS picks an ephemeral port for us.

    if stun_servers is None:
        # If a STUN server isn't provided, use a random one from the STUN_SERVERS:
        #stunHost, stunPortStr = random.choice(STUN_SERVERS).split(':')
        #stunPort = int(stunPortStr)
        stunServer = random.choice(STUN_SERVERS)
    else:
        # Pick a random STUN server from sources to use.
        stunServer = random.choice(stun_servers)

    # Turn the '0.0.0.0:54320' string in stunServer to '0.0.0.0' and 54320:
    stunHost, stunPortStr = stunServer.split(':')
    stunPort = int(stunPortStr)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sockObj:
        sockObj.settimeout(2)
        sockObj.bind((SOURCE_IP, SOURCE_PORT))

        # STUN transaction IDs are 16 arbitrary bytes:
        transID = bytes(random.randrange(256) for _ in range(16))

        # STUN Binding Request: 2-byte type, 2-byte length (0), 16-byte transaction ID.
        data = BIND_REQUEST_MSG + b'\x00\x00' + transID
        attempts_remaining = 3
        while True:
            # Loop until we get a response or run out of retry attempts.
            try:
                sockObj.sendto(data, (stunHost, stunPort))
            except socket.gaierror as exc:
                # Most likely you are offline.
                _log.debug('STUN sendto failed for %s: %r', stunServer, exc)
                return None

            try:
                buf, addr = sockObj.recvfrom(2048)
                break
            except Exception as exc:
                attempts_remaining -= 1
                if attempts_remaining == 0:
                    _log.debug('STUN recvfrom from %s gave up after retries: %r', stunServer, exc)
                    return None  # Could not connect to the stun server.

        if buf[0:2] != BIND_RESPONSE_MSG or buf[4:20] != transID:
            # Malformed or unexpected response; let the caller try a different server.
            _log.debug('STUN %s sent unexpected response: type=%s transIDMatch=%s',
                       stunServer, buf[0:2].hex(), buf[4:20] == transID)
            return None

        message_remaining = int.from_bytes(buf[2:4], 'big')
        base = 20
        while message_remaining:
            stunAttribute = buf[base:base + 2]
            stunAttributeLength = int.from_bytes(buf[base + 2:base + 4], 'big')

            if stunAttribute == MAPPED_ADDRESS:
                # Inside a MAPPED_ADDRESS attribute the layout is:
                #   [0:1]  reserved (0)   [1:2]  address family
                #   [2:4]  mapped port    [4:8]  IPv4 address
                return socket.inet_ntoa(buf[base + 8:base + 12])
            # All other STUN attributes are ignored.

            base += STUN_ATTR_LEN + stunAttributeLength
            message_remaining -= STUN_ATTR_LEN + stunAttributeLength

        # No MAPPED_ADDRESS attribute was found in the response.
        return None



def _profile_stun_servers():
    """Run this to get the response times of the STUN servers in STUN_SERVERS."""
    import time
    import pprint
    results = []
    for stunServer in STUN_SERVERS:
        elapsedTimes = []
        for i in range(3):  # Get the average of 3 timings.
            startTime = time.time()
            resultIp = _get_ip_from_stun([stunServer])
            elapsedTimes.append(round(time.time() - startTime, 2))
            time.sleep(0.1)  # Maybe this pause is not needed? I'm being superstitious.
        elapsedTime = sum(elapsedTimes) / 3
        print('DEBUG:', (stunServer, resultIp, elapsedTime))
        results.append((stunServer, resultIp, elapsedTime))
    results.sort(key=lambda x: x[2])
    pprint.pprint(results)
    results_for_STUN_SERVERS_constant = [i[0] for i in results if i[2] < 0.3 and i[1] is not None]  # 0.3 second max response time.
    return tuple(results_for_STUN_SERVERS_constant)


def _profile_https_servers():
    """Run this to get the response times of the HTTPS servers in IP_WEBSITES."""
    import time
    import pprint
    results = []
    for ipWebsite in IP_WEBSITES:

        startTime = time.time()
        resultIp = _get_ip_from_https(web_servers=[ipWebsite])
        elapsedTime = round(time.time() - startTime, 2)
        print('DEBUG:', (ipWebsite, resultIp, elapsedTime))
        results.append((ipWebsite, resultIp, elapsedTime))
    results.sort(key=lambda x: x[2])
    pprint.pprint(results)
    results_no_times = [(i[0], i[1]) for i in results if i[2] < 2.0]  # 2 second max response time.
    pprint.pprint(results_no_times)
    return results_no_times
