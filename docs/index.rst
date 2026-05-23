WhatIsMyIP
==========

``whatismyip`` is a small, dependency-free Python module for fetching your
public IP address from external sources (STUN servers and HTTPS endpoints).

Install
-------

.. code-block:: shell

   pip install whatismyip

Quick example
-------------

.. code-block:: python

   >>> import whatismyip
   >>> whatismyip.amionline()
   True
   >>> whatismyip.whatismyip()
   '69.89.31.226'
   >>> whatismyip.whatismyipv4()
   '69.89.31.226'
   >>> whatismyip.whatismyipv6()
   '2345:0425:2CA1:0000:0000:0567:5673:23b5'
   >>> whatismyip.whatismylocalip()  # Local IPs of all network cards.
   ('192.168.189.1', '192.168.220.1', '192.168.56.1', '192.168.1.201')
   >>> whatismyip.whatismyhostname()
   'GIBSON'

API reference
-------------

.. automodule:: whatismyip
   :members: whatismyip, whatismyipv4, whatismyipv6, whatismylocalip,
             whatismyhostname, amionline
   :undoc-members:
   :show-inheritance:

Module-level constants
~~~~~~~~~~~~~~~~~~~~~~

* ``IP4_WEBSITES`` — HTTPS endpoints that return your IPv4 address.
* ``IP6_WEBSITES`` — HTTPS endpoints that return your IPv6 address (falling
  back to IPv4 if no IPv6 is available).
* ``IP_WEBSITES`` — Union of the two above.
* ``STUN_SERVERS`` — Public STUN servers, ordered by recent response time.
* ``ONLINE_WEB_SERVERS`` — Popular hosts used by :func:`amionline` to probe
  connectivity.

Indices
-------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

.. toctree::
   :hidden:
