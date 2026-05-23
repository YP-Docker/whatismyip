import socket
import urllib.request

import pytest
import whatismyip


def test_basic():
    # This is a fake web page I set up on my inventwithpython.com website.
    assert whatismyip.whatismyip(sources=('https://inventwithpython.com/_whatismyiptest.html',)) == '99.99.99.99'

    # Check that these don't cause exceptions:
    assert whatismyip.whatismyip()
    assert whatismyip.whatismyipv4()
    assert whatismyip.whatismyipv6()
    # whatismylocalip() can return () on machines whose hostname doesn't
    # resolve (common on macOS), so just verify the call doesn't raise.
    whatismyip.whatismylocalip()
    assert whatismyip.whatismyhostname()
    assert whatismyip.amionline()
    assert whatismyip.amionline(web_servers=whatismyip.ONLINE_WEB_SERVERS)


def test_can_connect_to_whatismyip_websites():
    for url in whatismyip.IP4_WEBSITES + whatismyip.IP6_WEBSITES:
        try:
            urllib.request.urlopen(url, timeout=5).read()
        except Exception as exc:
            pytest.fail('Could not reach IP website {}: {!r}'.format(url, exc))


def test_can_connect_to_stun_servers():
    for server in whatismyip.STUN_SERVERS:
        ip = whatismyip._get_ip_from_stun([server])
        if ip is None:
            pytest.fail('Could not reach STUN server {}'.format(server))


def test_can_connect_to_connectivity_websites():
    for server in whatismyip.ONLINE_WEB_SERVERS:
        try:
            socket.getaddrinfo(server, 'www')
        except socket.gaierror as exc:
            pytest.fail('Could not resolve connectivity host {}: {!r}'.format(server, exc))


if __name__ == "__main__":
    pytest.main()
