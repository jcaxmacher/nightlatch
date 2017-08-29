|icon| Nightlatch
-----------------

Opening TCP port 22 to the complete public internet (0.0.0.0/0) is bad idea no matter how hardened
your server is and `AWS Trusted Advisor` will tell you as much.
Nightlatch is tool which improves the security of accessing `Amazon Web Services`_ EC2 instances
from various and changing public I.P. addresses.  It assumes an already existing `Bastion host`_
with a public I.P. address running on EC2.

Nightlatch is composed of a Serverless_ application (paired with a CloudFormation template you can
use to deploy the application within your AWS account) and command-line utility to request temporarily opening
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

Single-digit-sized groups of people managing EC2 instances using a Bastion host in a personal
or small/semi-professional AWS account.

Solutions that are better or bigger than Nightlatch
+++++++++++++++++++++++++++++++++++++++++++++++++++

1. Not needing to SSH into your servers at all by using `Immutable Infrastructure`_ and `Centralized Log Aggregation`_.
2. Having one or more dedicated public I.P. addresses used by workstations SSHing into your Bastion host.
3. An IPsec VPN connection
4. AWS Direct Connect (optionally with an IPsec VPN connection fallback)

.. _Immutable Infrastructure: https://martinfowler.com/bliki/ImmutableServer.html

.. _Centralized Log Aggregation: http://jasonwilder.com/blog/2012/01/03/centralized-logging/

Limitations
===========

At any given moment, a VPC security group can, by default, have a maximum of 50 rules.  If you request limit
increases with AWS support, you can push that number to 250.  This means that the maximum number of
I.P. addresses that Nightlatch could possibly grant access to at any given moment is 250 (assuming you
are only opening one TCP port per IP address).  That is way too many addresses.

Additionally, the data model used for bookkeeping of the ingress authorizations is stored in DynamoDB
and is not optimized for a large amount of data.  Theoretically, it could store ~6,000 authorizations,
but you would be paying excessive RCUs/WCUs because it's all stored in one item.

As stated above, if you have more than nine people using Nightlatch to access your EC2 instances, you would
probably be better served by a different solution.

Nightlatch only supports TCP connections because those `connections are tracked`_ by AWS unlike UDP traffic.
Because the opening and closing of inbound traffic on the desired TCP port(s) is performed through
VPC security group(s), the ingress rule can be removed while any connections created while the rule was in
place are allowed to remain.

.. _`connections are tracked`: http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-network-security.html#security-group-connection-tracking

TODO
====

* ``[X]`` DynamoDB bookkeeping table schema design
* ``[X]`` Function for adding ingress rule
* ``[X]`` Function for removing expired ingress rules
* ``[X]`` Configurable security group tag, TCP port(s) for ingress rule(s), ingress rule ttl
* ``[ ]`` CloudFormation template for deployment

Attribution
===========

Icon made by Freepik_ from www.flaticon.com_ is licensed by `CC 3.0 BY`_

.. _Freepik: http://www.freepik.com

.. _www.flaticon.com: https://www.flaticon.com/

.. _CC 3.0 BY: http://creativecommons.org/licenses/by/3.0/
