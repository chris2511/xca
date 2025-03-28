
.. admonition:: Abstract

  This application is intended for creating and managing X.509 certificates,
  certificate requests, RSA, DSA and EC private keys, Smart-cards and CRLs.
  Everything that is needed for a CA is implemented.
  All CAs can sign sub-CAs recursively. These certificate chains are
  shown clearly.
  For an easy company-wide use there are customisable templates that
  can be used for certificate or request generation.
  All cryptographic data is stored in a SQL database.
  SQLite, MySQL (MariaDB), PostgreSQL and MicrosoftSQL (ODBC) databases
  are supported.


Introduction
============

This application is intended as certificate- and key-store and as
signing application issuing certificates.

All data structures (Keys, Certificate signing requests, Certificates
and Templates) can be imported and exported in several formats like DER or PEM.
Import means reading a file from the filesystem and storing the data structure
into the database file, while exporting means to write the data structure
from the database file to the filesystem to be imported into an
other application.

When opening a new database the first time, it needs a password to encrypt the
private keys in the database. This is the default password. Every time this
database is opened the application asks for the password. This input dialog
may be canceled and the database is still opened successfully.
However, the access to the keys is not possible without supplying the
correct database password every time a key is used.

When setting an empty password, XCA will never ask again for a password
when opening this database. This can be useful when playing around with
test certificates or if all private keys are on security tokens.

The database password can be changed by the Menu item *Extra->Change DataBase password*

The different cryptographic parts are divided over 5 Tabs:
 Keys, Requests, Certificates, Templates and Revocation lists.

All items can be manipulated either by a context menu available by
right-clicking on the item, or by using the buttons at the right border.
Every item is identified by an internal name which is always shown in
the first column as long as the columns are not reordered by the user.

File Formats
------------

There are several default file formats to exchange cryptographic data with
other applications.

DER : Distinguished Encoding Rules
  is the binary ASN.1 encoding of the data.

PEM : Privacy Enhanced Mail
  is the base64 encoded version of the DER formatted data with additional
  header and footer lines to be transported via e.g. E-mail.
PKCS#X : Public Key Cryptography Standards
  published by https://www.rsa.com

Copyright
---------

.. include:: COPYRIGHT

