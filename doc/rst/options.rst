
.. index:: options (options)
.. _options:

Options
=======

The options dialog can be found in the file menu. All options are saved
in the database and do not depend on the operating systems registry or
configuration files.

- String settings

  This option applies to all strings converted to ASN1 strings.
  The selected string type is automatically set to
  the smallest possible and allowed type, covering all contained characters.

  The list of allowed string types can be selected:

  - **PKIX in RFC2459 (default):** All string types are
    set as described in RFC2459
  - **No BMP strings:**  All strings containing non printable
    characters are regarded as errors.
  - **PKIX UTF8 only:**  All string types are selected according to
    RFC2459 for entities issued after 2004, which means that almost all
    distinguished name entry types are set to UTF8.
  - **All strings:** All string types are allowed.

- Default hash algorithm

  Older Windows versions and OpenSSL versions can not handle
  SHA256 and SHA512. This option allows to set the hash algorithm to SHA1
  for instance.

- Suppress success messages

  After importing and generating new items a success message is shown.
  This switch disables the messages.

- Don't colorize expired certificates

  Since version 0.9.2 the expiration dates of certificates will be colorized.
  Red means expired or not yet valid. Yellow indicates certificates that only
  have 4/5 of their lifetime until expiration.
  The CRL expiration date will be marked red 2 days before expiration.
  With this option, the colorization can be disabled.

- Translate established x509 terms

  It is usually more clear to read "commonName" instead of
  e.g (german) "Allgemeine Bezeichnung".
  Same is true for "Extended key usage" or "Basic constraints".
  With this setting the translated terms are shown and the Tool-Tip of the
  entry shows the established term.
  If not set, the established term will be displayed
  and the Tool-Tip contains the translation.

- Only use hashes supported by the token when signing with a token key

  The PKCS#11 token does probably not support all possible hashes for
  a signature operation. I.e. the EC and DSA signing algorithms are currently
  only defined with SHA1 in the PKCS#11 specification.

  XCA does the hashing part of the digital signature in software outside
  the token and uses the token to sign the hash.
  That's why XCA may use additional hashing algorithms like ecdsaWithSha256.

  If other applications that probably use the token hashing algorithms shall
  use the token, this option should be set.

- Disable legacy Netscape extensions

  With this option set the input and use of the legacy Netscape extensions
  will be suppressed. The certificate input dialog has no Netscape tab,
  the request and certificate columns don't show the Netscape extensions
  and when applying a template or converting certificates,
  the Netscape extensions are removed.
  However, the details of certificates and requests still show the
  Netscape extensions if they exist.

- Mandatory subject entries

  A list of mandatory distinguished name entries may be specified to
  get a warning, whenever issuing a certificate that lacks one or more listed
  entries. This requirement is not checked when editing templates,
  because templates may have empty entries that will be filled during
  the rollout of the certificate.

- Explicit subject entries

  This list may be used to change the list of the usual 7 distinguished
  name entries shown in the subject tab of the Certificate / Request / Template
  generation dialog to better fit ones needs.

  When activating the *Dynamically arrange explicit subject entries* option,
  the explicit entries are rearranged by the name to be edited.

  If the name is empty, the entries are unchanged. Otherwise, the entries of
  the name to be edited are displayed first, followed by the entries of the
  list above not mentioned in the name to be edited.

- PKCS#11 provider

  Here you can select the path to one or more PKCS#11 libraries on your system.
  If the list is empty, the *Token* menu will be unavailable.

