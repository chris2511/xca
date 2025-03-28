.. index:: crldetail (crldetail)

Certificate Revocation Lists
============================

All certificates are issued for a restricted period of time.
However it may happen that a certificate should not be used or becomes invalid
before the *not after* time in the certificate is reached. In this case
the issuing CA should revoke this certificate by putting it on the list of
revoked certificates, signing the list and publishing it.

.. index:: crlgenerate (crlgenerate)

Generation of CRLs
------------------

In XCA this can be done by the context-menu of the CA and the
*revoke* entry in the context-menu of the issued certificate.
First all invalid certificates must be marked as revoked and
then a Certificate Revocation List should be created and will be stored in the
database.

The validity times define start and expiry date of the CRL. The default
interval can be configured in the :ref:`ca_properties` dialog.

The options section allows to select, whether the Subject Alternative Name
and the Authority Key Identifier of the issuing CA should be placed into
the CRL. The CRL Number (https://tools.ietf.org/html/rfc5280#section-5.2.3)
will be tracked by XCA and updated on every use.

There is also a commandline option to issue a CRL:

.. code-block:: bash

  xca --crlgen="My Ca" --pem --print

.. index:: crlexport (crlexport)

CRL Export
----------

Certificate Revocation Lists can be exported by the context-menu or by the button on the right.

- **Clipboard** Writes all selected requests in PEM format to the Clipboard.
- **File:** Write the request into a file.
  The filename can be selected in the export dialog and the Export format:

.. include:: export-revocation.rst

.. index:: crlmanage (crlmanage)

Manage revocations
------------------

Revoked certificates may be managed without the revoked certificate
in the database. The revocations are stored inside the database for each CA
with revocation date, revocation reason and invalidation date.
They get automatically updated when importing a CRL of this CA
or by manually revoking an issued certificate.
The Manage revocations dialog is accessible by the CA submenu of the
context menu of the CA.
Entries can be added, deleted and modified.

.. index:: crlrevocation (crlrevocation)

Revocation properties
---------------------

The certificate revocation happens by the CA at the *revocation date* which
is the time when the revocation is performed. The *invalidity date* can be set
to an earlier time in this dialog. The *revocation reason* is explains why
the certificate has been revoked.
https://tools.ietf.org/html/rfc5280#section-5.3
