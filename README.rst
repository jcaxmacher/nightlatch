|icon| Latchbolt
----------------

Latchbolt is both a Serverless_ application and command-line utility for temporarily opening
TCP port 22 from a specific I.P. address to a `Bastion host`_ running on `Amazon Web Services`_ (AWS).
It's akin to `Port knocking`_ using AWS APIs.

.. |icon| image:: assets/key.png
          :width: 1em

.. _Serverless: https://en.wikipedia.org/wiki/Serverless_computing

.. _Bastion host: https://en.wikipedia.org/wiki/Bastion_host

.. _Amazon Web Services: https://aws.amazon.com

.. _Port knocking: https://en.wikipedia.org/wiki/Port_knocking

Who would want to use this?
===========================

Single digit-sized groups of people managing EC2 instances using a Bastion host in a personal
or small/semi-professional AWS account.
Companies of any significant size will be better off configuring an IPsec VPN connection, using
AWS Direct Connect or both.

Attribution
===========

Icons made by Freepik_ from www.flaticon.com_ are licensed by `CC 3.0 BY`_

.. _Freepik: http://www.freepik.com

.. _www.flaticon.com: https://www.flaticon.com/

.. _CC 3.0 BY: http://creativecommons.org/licenses/by/3.0/
