
.. index:: csrdetail (csrdetail)
.. _csr:

Certificate Signing Requests
============================

Certificate signing requests are described in PKCS#10 standard.
They are used to supply a Certification Authority with the
needed information to issue a valid certificate
without knowing the private key. This includes personal information,
the public key and additional extensions.

It is not necessary to generate a request prior to signing it by your CA
or before self-signing it. Simply start generating the certificate directly.
People using the OpenSSL command line tools are used to generate a request
with `"openssl req -new ...` and then signing it.
This is not necessary with XCA.

Tracking signed CSR with XCA can be done by the *Signed* and
*Certificate count* columns of the certificate signing request tab.
The *Signed* column is an information stored in the database
whenever a CSR was used to issue a certificate. Also an automatic comment
is left in the comment of the CSR in this case.
It does not depend on the certificate remaining in the XCA database.
The *Certificate count* column on the other hand displays the number of
currently available certificates with the same public key in the database.

.. index:: csrgen (csrgen)

Generating a new Request
------------------------

After clicking on the *New Request* button, the Certificate dialog
will be started to ask all needed information for generating a new Request.
See: :ref:`wizard`

The request generation can also be invoked by the context menu of a
certificate *Transform->Request*. This menu point is only available
if the private key of the certificate is available.

In this case all needed data is copied from the certificate and the
Certificate dialog is not invoked.

.. index:: csrexport (csrexport)

Request Export
--------------

Requests can be exported by the context-menu or by the button on the right.

- **Clipboard** Writes all selected requests in PEM format to the Clipboard.
- **File** Write the request into a file in PEM or DER format.
- **OpenSSL config** Create and store an OpenSSL configuration file which
  can be used to generate a similar request with openssl
  `openssl req -new -config <file>`

Request Transformation
----------------------

A request transformation creates a new database entry based on the
selected request

- **Template** Create an XCA template with the values of the request.
- **Public Key** Extract the public key from the request and store it
  in the Private Keys Tab.
- **Similar Request** Starts the Certificate input dialog preset with
  all values from the current request to create a new request.

Request Details
---------------

All information contained in the request are shown. If the key-store contains
the private key corresponding to the request the keys internal name is shown
in the *Key* field, which can be clicked to show it.

