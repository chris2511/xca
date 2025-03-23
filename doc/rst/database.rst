
Database
========

.. index:: remote_db (remote_db)

.. _remote_database:

Remote Databases
----------------

XCA supports connections to network databases. Tested engines are:

 - MariaDB / mySQL
 - PostgreSQL
 - Microsoft SQLserver

Table prefix
''''''''''''

The table prefix can be used to store more than one XCA database in the same
remote database.

Database Drivers
''''''''''''''''

The SQL backend drivers provided by the manufacturer of the database must be
installed additionally to the Database support in XCA.

Linux
.....

The backend drivers are provided by your distribution:

 - **Debian**: *libqt6sql6-psql*, *libqt6sql6-mysql* or *libqt6sql6-odbc*.
 - **RPM**: *libqt6-database-plugin-pgsql*, *libqt6-database-plugin-mysql*,
   *libqt6-database-plugin-odbc*

They should pull in all necessary dependencies.

Apple macos
...........

 - **PostgreSQL**: Install the https://postgresapp.com/
 - **ODBC**: It requires the /usr/local/opt/libiodbc/lib/libiodbc.2.dylib.
   When installing unixodbc via brew the library must be symlinked from
   /opt/homebrew/Cellar/libiodbc/3.52.16/lib/libiodbc.2.dylib
 - **MariaDB**: Since XCA-2.8.0 the MariaDB plugin is included in the
   xca.app bundle. No additional installation is required.

Windows
.......

 - **PostgreSQL**: https://www.enterprisedb.com/downloads/postgres-postgresql-downloads
   (Commandline tools are sufficient). Add the *bin* directory of the Postgres
   installation directory to your PATH (C:\\Program Files\\PostgreSQL\\16)
 - **ODBC**: Use the *ODBC Datasources 64bit* app to configure the SQL Server.
   If the data source is configured completel, only the matching DSN is required
   in the XCA connection settings.
 - **MariaDB (MySQL)**: Install the Plugin from here:
   https://github.com/thecodemonkey86/qt_mysql_driver. Select the MinGW variant
   and install it as documented.

Driver specific configurations
..............................

Additional options for the database connection can be set in configuration files.
They must be put in the XCA configuration directory, which is displayed in the about dialog.
If there is already a file called *dbhistory* then you know you are in the right place.
The options-file must be named after the database driver, e.g. *QPSQL*, *QMYSQL* or *QODBC*
optionally followed by a dash and the database-hostname (exactly as used in the connection settings
including an optional port number) and a *.options* extension.

Examples:

 - QMYSQL-192.168.12.13.options
 - QPSQL.options

Also the environment variable XCA_<driver-name>_OPTIONS may be used to set the options.

The file must contain the options as ; separated key=value pairs. The recognized options depend
on the database driver. See:

 - https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-PARAMKEYWORDS for PostgreSQL and
 - https://doc.qt.io/qt-6/sql-driver.html#connection-options for MySQL and
 - https://doc.qt.io/qt-6/sql-driver.html#odbc-unicode-support for ODBC.

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

Extract the certificate with internal name 'rootca' from the database::

  sqlite3 ~/xca.xdb "SELECT cert FROM view_certs WHERE name='rootca'" | base64 -d | openssl x509 -inform DER

Extract the public part of a key by database primary key::

  sqlite3 ~/xca.xdb "SELECT public from view_public_keys WHERE id=3" | base64 -d | openssl pkey -inform DER -pubin

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

