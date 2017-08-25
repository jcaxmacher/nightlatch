|icon| Nightlatch
-----------------

Opening TCP port 22 to the complete public internet (0.0.0.0/0) is bad idea no matter how hardened
your server is and `AWS Trusted Advisor` will tell you as much.
Nightlatch is tool which improves the security of accessing `Amazon Web Services`_ EC2 instances
from various and changing public I.P. addresses.  It assumes an already existing `Bastion host`_
with a public I.P. address running on EC2.

Nightlatch is composed of a Serverless_ application (along with a CloudFormation template you can
use to deploy it within your AWS account) and command-line utility to request temporarily opening
TCP port 22 from a source workstation (where the CLI is run) to the `Bastion host`_.
It's akin to `Port knocking`_ using AWS APIs.  However, Nightlatch does not prevent you from also using
Port knocking.  Security is a `game of layers`_.

.. |icon| image:: assets/key.png
          :width: 1em

.. _Serverless: https://en.wikipedia.org/wiki/Serverless_computing

.. _Bastion host: https://en.wikipedia.org/wiki/Bastion_host

.. _Amazon Web Services: https://aws.amazon.com

.. _Port knocking: https://en.wikipedia.org/wiki/Port_knocking

.. _game of layers: https://en.wikipedia.org/wiki/Layered_security

.. _AWS Trusted Advisor: https://aws.amazon.com/premiumsupport/trustedadvisor/

Who would want to use this?
===========================

Single digit-sized groups of people managing EC2 instances using a Bastion host in a personal
or small/semi-professional AWS account.

Solutions that are better or bigger than Nightlatch
+++++++++++++++++++++++++++++++++++++++++++++++++++

1. Not needing to SSH into your servers at all by using `Immutable Infrastructure`_ and `Centralized Log Aggregation`_.
2. Having one or more dedicated public I.P. addresses used by workstations SSHing into your Bastion host.
3. An IPsec VPN connection
4. AWS Direct Connect (optionally with an IPsec VPN connection fallback)

.. _Immutable Infrastructure: https://martinfowler.com/bliki/ImmutableServer.html

.. _Centralized Log Aggregation: http://jasonwilder.com/blog/2012/01/03/centralized-logging/

Attribution
===========

Icon made by Freepik_ from www.flaticon.com_ is licensed by `CC 3.0 BY`_

.. _Freepik: http://www.freepik.com

.. _www.flaticon.com: https://www.flaticon.com/

.. _CC 3.0 BY: http://creativecommons.org/licenses/by/3.0/
