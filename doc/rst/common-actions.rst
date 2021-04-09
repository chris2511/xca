
Common Actions
==============

Many actions are common to all cryptographic parts and are mentioned
here once for all.
The goal of this application is to provide an easy to use signing-tool and
also a common place for all selected PKI items like requests or certificates.

.. _columns:
.. index:: columns (columns)

Column Handling
---------------

Column visibility can be changed by the context menu of the table header
or the "columns" sub menu of the table context menu.
It shows all available columns with check-boxes to show or hide them.

- Column actions

  - **Reset**
    Reset column order and visibility to the default.
  - **Hide Column**
    Hide the current column.
    Only shown in the context menu of the column header.

- Common columns

  - **Internal name**
    Name of the item in the database.
  - **No.**
    A simple counter to easily count the items.
  - **Primary key**
    Unique number to identify an item in the database.
    See :ref:`primary_key`.
  - **Date**
    Date of the appearance in this XCA database.
    See :ref:`date_and_source`
  - **Source**
    Origin of this item, See :ref:`date_and_source`.
  - **Comment**
    A multi-line free text input, see :ref:`comment`.

- Certificate and request columns

  - **Subject**
    The complete subject name.
  - **Subject hash**
    Subject hash used by OpenSSL to lookup certificates. See
    https://www.openssl.org/docs/man1.0.2/apps/c_rehash.html
  - **Subject entries**
    Displays single entries of the subject.
    The list represents the content of the :ref:`objectids` file.
  - **X509v3 Extensions**
    Displays a textual representation of the selected extension.
  - **Key name**
    Internal name of the key in the private keys tab.
  - **Signature algorithm**
    Signature algorithm used to sign the certificate or request.

- Request columns

  - **Signed**
    Whether the request is already signed or not.
  - **Unstructured name**
    CSR specific attribute.
  - **Challenge password**
    CSR specific attribute.
  - **Certificate count**
    Number of certificates in the database with the same public key.

- Certificate columns

  - **CA**
    CA Basic Constraints flag
  - **Serial**
    Serial number
  - **MD5 / SHA1 / SHA256 fingerprint**
    Certificate fingerprint

Columns can be resized and rearranged.
This configuration is stored in the database and will be reassigned next time
this database is opened.

.. index:: import (import)

Importing items
---------------

The import of an item can be done by either clicking the import button
on the right or via the context menu available by right clicking into the list.
The import function is smart enough to probe all known formats independent
of the file extension:

Keys
  PEM private key, PEM public key, DER private key,
  DER public key, PKCS#8 private key, SSH public key.
Requests
  DER request, PEM request
Certificates
  DER certificate, PEM certificate
  (PKCS#12 and PKCS#7 certificates must be imported with an
  extra button, because they may contain more than
  one certificate and key)

After selecting the filename XCA will probe for the known formats of that item
and in case of an error it prompts the *last* OpenSSL error message.
It is possible to select more than one file by selecting them with SHIFT click.

Also the *Import* menu may be used to load items. Next to the file-types
above, it also supports *PEM* import. PEM describes the encoding
instead of the file-type. So a PEM file can be any type of private key, CRL
certificate or CSR. This import facility discovers the type and loads it.

When importing more than one Key, CRL, Certificate or Request
all items are shown in a Multi-import dialog.
When importing a PKCS#7 or PKCS#12 item, the contained keys
and certificates are shown in the Multi-import dialog.
By using the Multi-import dialog the items can be examined, imported or dropped.

After reading the item it searches for this item in the database and if it
is unique, the item is stored in the database. Otherwise it shows a message
containing the internal name of this item in the database.

Details of an Item
------------------

The details dialog can be accessed by double clicking the item,
by the context menu or by the button on the right.
The names of the issuers certificate and the corresponding key
are click-able and their content will be shown on "double-click"

Renaming an Item
----------------

An Item can be renamed via the context menu by right-clicking on the item,
by pressing &lt;F2&gt; or by the <em>Rename</em> button on the right border.

Deleting Items
--------------

Items can be deleted by the button on the right or via the context menu.
Certificate signing requests can be deleted
when they got signed, because they are not needed anymore.
The request can be recovered from the resulting certificate by
transforming the certificate to a request.
This is however only possible if you own the private key of the
certificate. Multiple items may be selected to delete them all at once.

Searching Items
---------------

The displayed list of items can be reduced by the search-input at the
bottom right. It affects all tabs. It does not only search inside the displayed columns but the whole content of the items. It searches the internal name,
issuer, subject, extensions, PKCS#10 attributes and token provider.

.. _internal_name:

Internal name
-------------

The internal name is only used inside the database and is intended
to uniquely identify the items. In earlier versions of XCA this name
had to be unique. This is not a requirement anymore.

.. _date_and_source:

Date and source of appearance
-----------------------------

XCA tracks the time and source of any newly appeared item.
Both can be seen when selecting *Properties* in the
context menu of an item, or by enabling the *Source* or
*Date* columns.

The source may be one of the following

- Imported:
    From a file or by pasting PEM data
- Generated
    Created by XCA
- Transformed
    Converted from an other item by the "transform" context menu
- Token
    The device has been initiall read from a hardware token
- Legacy Database
    The item was already present in a legacy XCA database that
    did not track the Source information.

The content of the date and source fields will never be
part of an exported item.

.. index:: comment (comment)

.. _comment:

Comment
-------

XCA allows to insert multi-line comments for all items. They can be edited
by the properties dialog. When showing the *Comment*
column, it will display the first line of the comment field.

XCA itself uses the comment field of certificates and requests
to leave a note during important operations:

- Applied templates during certificate or request generation
- Generated keys during certificate or request generation
- Signing date, time and internal name of the issuing CA when
  a request gets signed.
- File name when the item got imported from a file.

The content of the comment field will never be part of an exported item.

.. _primary_key:

Database primary key
--------------------

When inserting an item into the database a new, unique id
will be generated and used as primary key in the database.
If the item shall be found in the database by external tools,
the *items.id* can be used to uniquely identify the item.
The internal name cannot be used, since it is not necessarily unique anymore.

This ID will never be used outside the database.

.. index:: itemproperties (itemproperties)

Item properties
---------------

Common properties can be displayed and edited for all items:

- Internal name :ref:`internal_name`
- Comment :ref:`comment`
- Date and source :ref:`date_and_source`
