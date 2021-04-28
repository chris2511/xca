
.. index:: certdetail (certdetail)
.. _certificates:

Certificates
============

All certificates from the database are displayed in a tree view reflecting
the chain dependencies.
If there is a CA certificate and several client certificates signed by this CA,
the client certificates can be shown by clicking on the plus sign of the
CA certificate.

.. _ca_cert:

CA certificates
---------------

XCA will recognize CA certificates if the CA flag in the *Basic Constraints*
is set to true. If there is a corresponding private key, the *CA*
sub-menu in the context-menu will be enabled.

For building the chains the CA flag is disregarded, because there are some
CAs without this flag.
Instead it considers the issuer name and the signature to decide which
certificate is the issuer.

If there is more than one CA certificate with the same subject and private key,
it is undeterminable which one was selected during the signing process.
This is not an issue.
This usually happens if a CA certificate got renewed.
In this case XCA selects the certificate with the later expiry date as
anchor for the issued certificates.

.. index:: ca_properties (ca_properties)
.. _ca_properties:

CA Properties
-------------

For every CA a default template can be configured that will be automatically
applied when creating a new certificate.
The CRL days define the preset expiry time to the next CRL release when issuing a new CRL.

.. index:: certgen (certgen)

Generating certificates
-----------------------

After clicking on the *New Certificate* button the Certificate input dialog
will be started to ask all needed information for generating a new Certificate.
See: :ref:`wizard`.
Certificate creation can also be invoked by the context menu of the
certificate list background or by the context menu of the request.
In this case the Certificate input dialog is preset with the request
to be signed.

If a *CA certificate* is selected in the certificate list, this
certificate will be preselected as issuing certificate.

Certificate details
-------------------

The signer is the internal name of the issuers certificate,
*SELF SIGNED* if it is self signed or *SIGNER UNKNOWN* if the issuer's
certificate is not available.
The validity is set to *valid* if the certificate's dates are valid
or to *Not valid* if they are not, compared to the internal
time and date of the Operating System.

If the certificate is revoked, the revocation date will be shown instead.

On the *Subject* and *Issuer* tab the distinguished name is
also displayed in a format defined in RFC2253 for copy&paste.

.. index:: certexport (certexport)

Certificate Export
------------------

- **Clipboard:** Copy all selected certificates to the clipboard as PEM file
- **File:** Export to external file.
  The filename can be selected in the export dialog and the Export format:

  - **PEM:** PEM encoded
  - **PEM with Certificate chain:** PEM encoded certificate
    and all issuers up to the root certificate in one file
  - **PEM all trusted Certificates:** List of all PEM encoded
    certificates that are marked as *Always trusted*
    (usually all self-signed certificates) in one file for e.g.
    apache as trusted certificate store.
  - **PEM all Certificates:** All PEM encoded certificates in one file.
  - **DER:** DER encoded certificate.
  - **PKCS#7:** DER encoded PKCS#7 structure containing the certificate.
  - **PKCS#7 with Certificate chain:** DER encoded PKCS#7 structure containing
    the certificate and all issuers up to the root certificate.
  - **PKCS#7 all trusted Certificates:** DER encoded PKCS#7 structure
    containing all certificates that are marked as *Always trusted*
  - **PKCS#7 all Certificates:** DER encoded PKCS#7 structure
    containing all certificates.
  - **PKCS#12:** PKCS#12 structure containing the certificate
    and the corresponding private key
  - **PKCS#12:** PKCS#12 structure containing the certificate, the
    corresponding private key and the chain of all issuers certificates.
  - **PEM cert + key:** concatenation of the private key and certificate
    in a format used by apache or the X509 patch for OpenSSH.
  - **PEM cert + PKCS8 key:** concatenation of the
    private key in PKCS#8 format and certificate.

- **Token:** Store certificate on the Security token containing the private key.
- **Other token:** Store certificate on any Security token.
- **OpenSSL config:** Create an OpenSSL config file from the content of this
  certificate, which can be used to generate a similar certificate with
  openssl: `openssl req -new -x509 -config <file>`

When exporting PKCS#12 structures XCA asks later for an encryption password.

Certificate Transformation
--------------------------

A certificate transformation creates a new database entry
based on the selected certificate.

- **Public Key:** Extract the public key from the certificate and store it
  in the Private Keys Tab.
- **Request:** Create a PKCS#10 request by using the data from the certificate.
  The private key of the certificate must be available for this option.
- **Similar Certificate:** Starts the Certificate input dialog preset with all
  values from the current certificate to create a new certificate.
- **Template:** Create a XCA template with the values of the request.

Certificate revocation
----------------------

Certificates can only be revoked, if the private key of the issuer's certificate
is available. The certificate will be marked as revoked and the revocation date
and reason will be stored with the CA certificate.

If more than one unrevoked certificate of the same issuer is selected,
all of them will be revoked at once with the same revocation date and reason.
The context menu shows this by adding the number of selected certificates
in squared brackets.

To generate a CRL, revoke the appropriate certificates and select
*CA->Generate CRL* in the context-menu of the signing certificate.

Certificate renewal
-------------------

Certificates can only be renewed, if the private key of the issuer's certificate
is available. Renewal is done by creating a new certificate as a copy of the
original one with adjusted validity dates.

Use the *Revoke old certificate* check-box to automatically revoke the old
certificate.

If more than one certificate of the same issuer is selected,
all of them will be renewed at once with the same validity dates.
The context menu shows this by adding the number of selected certificates
in squared brackets.

CA special functions
--------------------

The context menu of CA certificates contains the *CA* sub-menu,
which makes the following functions available:

- **Properties:**

  - **CRL days:** The days until the next CRL release.
  - **Signing Template:** The default template for issuing certificates.

- **Generate CRL:** Generate the CRL by collecting all
  revoked certificates and their revocation date.
- **Manage revocations:** Displays all revocations and allows to
  manipulate them.
  Non existing certificates may be revoked by adding the serial number
  of the certificate. It is not required anymore to keep revoked certificates
  in the database, because the revocation information is stored together
  with the CA certificate.
