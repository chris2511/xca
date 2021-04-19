
Database
========

.. _extracting-items:

Extracting items
----------------

.. highlight:: bash

The sqlitebrowser may be used to examine the elements of the database.

The database schema is documented :ref:`database-schema`
All cryptographic items are stored as base64 DER format and must be
decoded before feeding them to OpenSSL::

  | base64 -d | openssl <x509|req|crl|pkcs8> -inform DER ...

Extract the private key with internal name 'pk8key' from the database::

  sqlite3 ~/xca.xdb "SELECT private FROM view_private WHERE name='pk8key'" | base64 -d | openssl pkcs8 -inform DER

Extract a CRL::

  sqlite3 ~/xca.xdb "SELECT crl FROM view_crls WHERE name='ca'" | base64 -d | openssl crl -inform DER

Modify the comment of an item with id 3::

  sqlite3 ~/xca.xdb "UPDATE items SET comment='My notes' WHERE id=3"

The item names are not required to be unique anymore.
Each table view in XCA has an optional column "Primary key" that may be
shown to get the ID of the item in the database.


.. _database-schema:

Schema
------

.. literalinclude:: database_schema.sql
   :language: sql

