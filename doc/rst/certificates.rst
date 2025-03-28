
.. _certificates:

X.509 Certificates
==================

All certificates from the database are displayed in a tree view reflecting
the chain dependencies.
If there is a CA certificate and several client certificates signed by this CA,
the client certificates can be shown by clicking on the plus sign of the
CA certificate.

.. _ca_cert:

CA Certificates
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

.. index:: certdetail (certdetail)

Certificate details
-------------------

The signer is the internal name of the issuers certificate in the database.
Or *SELF SIGNED* if it is self signed or *SIGNER UNKNOWN* if the issuer's
certificate is not available.
The validity is set to *valid* if the certificate's dates are valid
or to *Not valid* if they are not, compared to the internal
time and date of the Operating System.

If the certificate is revoked, the revocation date will be shown instead.

On the *Subject* and *Issuer* tab the distinguished name is
also displayed in a format defined in RFC2253 for copy&paste.

Certificate validation
^^^^^^^^^^^^^^^^^^^^^^

For end entity certificates an OpenSSL certificate validation and purpose checking is executed
and the result is shown in the *Validation* tab.
The Error codes and their meaning can be found in the
`OpenSSL documentation <https://docs.openssl.org/master/man3/X509_STORE_CTX_get_error/#error-codes>`_
or explained in more detail at https://x509errors.org/.
XCA also displays the internal OpenSSL error keyword for a better lookup.

The certificate purpose is described here: https://docs.openssl.org/master/man3/X509_check_purpose

.. index:: certexport (certexport)

Certificate Export
------------------

- **Clipboard:** Export certificates to the clipboard
- **Clipboard format:** The format for the clipboard can be selected as follows:

.. include:: export-x509-clp.rst

- **File:** Export to external file.
  The filename can be selected in the export dialog and the Export format:

.. include:: export-x509.rst

- **Token:** Store certificate on the Security token containing the private key.
- **Other token:** Store certificate on any Security token.

When exporting PKCS#12 structures XCA asks later for an encryption password.

Microsoft Cryptographic Service Provider (CSP)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The PKCS#12/PFX export function will include the CSP from the comment section
of the corresponding private key. The first line containing "CSP: <CSP Name>"
like **CSP: Microsoft Tatooine Sand Provider** will put the CSP Name into the PKCS#12 file.

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

Be careful with the "Keep serial number" option. A revocation will revoke both
certificates, because they have the same serial number. It is recommended to
either replace the old certificate or not use this option at all.

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
