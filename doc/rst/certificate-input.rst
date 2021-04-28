
.. index:: wizard (wizard)

.. _wizard:

Certificate Input Dialog
========================

This input dialog is the central part for collecting all data regarding certificates,
requests and templates. It will be invoked whenever such an item is going
to be created or, in case of a template, is altered.

.. index:: wizard_src (wizard_src)

Source
------

This page is not shown when creating or changing templates.

Signing Request
...............

If it is desired to either enroll a certificate from a PKCS#10 request
by a local CA, or to create a certificate from a request by self-signing it,
the request can be selected here. In the later case the private key of
the request must be available.

Signing
.......

Either self-signing or the CA certificate for signing may be selected here.
Additionally, the desired signing algorithm can be adjusted.
The drop-down list contains all :ref:`ca_cert` with an available private key.

Signature Algorithm
...................

Usually SHA256 or higher should be used, but
since older windows versions including XP can not handle them,
you may opt to use SHA1. The default signing algorithm may be
selected by the *Options* menu.

Templates
.........

The fields of the certificate can be preset by the values of a template
by selecting it and clicking *Apply all*.
Templates can be mixed by applying the subject of one template and then
applying the extensions of an other by using the
buttons *Apply subject* and *Apply extensions*

.. index:: wizard_subject (wizard_subject)

Personal Settings
-----------------

Subject
.......

On this Page all personal data like country, name and email address
can be filled in.
The *Country code* field must either be empty or exactly contain
two letters representing your country code; e.g. *DE* for Germany.
If you want to create an SSL-server certificate the *Common name*
must contain the DNS name of the server.
The subject-alternative-name extension must be used to define
additional DNS names, even wildcards. In this case
the CommonName must be repeated here, because TLS clients disregard the
CommonName in case the subject-alternative-name extension exists.
If the *internal name* is empty, the common name will be used
as internal name.
It will also be used as default internal name, if a new key is created here.

Other rarely used *name-entries* can be selected in the dialog below.
By using this table instead of the explicit entries above,
the order of the entries can be adjusted.
A new line can be added via the *Add* button.
The current line can be deleted via the *Delete* button.
Existing lines can be exchanged and reordered by moving the row-header
(containing the row-number) around.
All items can be added more than once, even those from above.
This is not very usual but allowed.

The list of the 7 explicit distinguished name entries may be adjusted in the options dialog
at :ref:`options`

Private Key
............

Keys can be generated here "on the fly" by pressing the button.
The name of the new key will be preset by the common name of the certificate.
The newly generated key will be stored in the database and stay there,
even if the input dialog is canceled. The drop-down list of the keys
only contains keys that were not used by any other certificate or
request. The key-list is not available for creating or changing templates.
By checking *Used keys too* the list contains all available
keys. Use this with care. You're likely doing something wrong when using this
option.

This tab does not appear when signing a request, because the request
contains all needed data from this tab.
Select "Modify subject of the request", if you want to modify it anyway.
The content of the subject Tab will then be preset with the content of the
request.

.. index:: wizard_extensions (wizard_extensions)
.. index:: wizard_keyusage (wizard_keyusage)
.. index:: wizard_netcape (wizard_netcape)

X509v3 Extensions
-----------------

The next three tabs contain all fields for adjusting the certificate extensions.
It is not in the focus of this document to explain them all in detail.
The most important are the *Basic Constraints* and the
*Validity* range.

More details can be found in
`RFC5280 <https://tools.ietf.org/html/rfc5280.html>`_.

Basic Constraints
.................

If the type is set to *Certification Authority*, the certificate is
recognized by XCA and other instances as issuer for other certificates.
Server-certificates or E-Mail certificates should set this extension to
*End entity* (strongly recommended) or disable it completely by setting
it to *Not defined*

Validity Range
..............

The *Not before* field is set to the current date and time of the
operating system and the *Not after* field is set to the current
date and time plus the specified time range.
When applying time ranges, the expiry date (not after) is calculated by taking
the currently configured start date (not before) and adding the time range.

For templates the specified times are not saved, because it does not
make much sense.
Rather the time range is stored and automatically applied when selecting this
template. Applying the time range means to set notBefore to "now" and notAfter
to "now + time range". If the *midnight* button is set both dates will be
rounded down and up to midnight.

.. index:: wizard_advanced (wizard_advanced)

Advanced
........

Any extension, not covered on the other tabs can be added here as
defined in OpenSSL nconf. The validity can be checked by clicking
*Validate*. All extensions from all tabs will be shown here
to see them all in their final form. Click on *Edit* to continue
editing the extensions here.

Refer to the OpenSSL X509v3 configuration for more details:
  https://www.openssl.org/docs/manmaster/man5/x509v3_config.html

Certificate Policies
''''''''''''''''''''

The following example of *openssl.txt* also works in the advanced tab
to define certificate policies

.. code-block:: ini

  certificatePolicies=ia5org,1.2.3.4,1.5.6.7.8,@polsect

  [polsect]

  policyIdentifier = 1.3.5.8
  CPS.1="http://my.host.name/"
  CPS.2="http://my.your.name/"
  userNotice.1=@notice

  [notice]

  explicitText="Explicit Text Here"
  organization="Organisation Name"
  noticeNumbers=1,2,3,4

Adding more than one AuthorityInfoAccess entry is also possible here:

.. code-block:: ini

  authorityInfoAccess=@aia_sect

  [aia_sect]

  OCSP;URI.1=http://www.some.responder.org/
  OCSP;URI.2=http://www.some.other-responder.org/
  caIssuers;URI.3=http://server.whatever.org/cert-path
  caIssuers;URI.4=ldap://server.whatever.org/xxx,yyy

When exporting existing Certificates to templates, the extensions will
be translated to OpenSSL config file format.

