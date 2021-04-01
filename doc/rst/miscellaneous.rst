
Miscellaneous
=============

Updating
--------

Usually XCA knows database formats used in previous versions and does
an automatic upgrade of the database if neccessary when opened the first time.

*Updating from versions earlier than 2.0.0*

Older versions of XCA used a simple serial
proprietary database for storing the cryptographic items.
Starting with version 2.0.0 this has changed to SQL.

For file based databases the SQLite database format is used.
Since XCA uses SQL, it can also be connected to a network database.
The databases *mySQL* *PostgreSQL* and *Microsoft SqlServer* are tested.
Please use the *Open Remote DataBase* menu item to connect to a remote host.

The main disadvantage of the old format leading to the switch to SQL
was the inaccessibility by external tools. Since years users ask for
command-line access to the database.

The new database can be queried by external tools like `sqlite3` or
`sqlitebrowser` to extract verify or modify content.
Please see :ref:`extracting-items`

.. Note::
  When opening a legacy database, it will be converted to the new format after
  backing up the original database.

.. Danger::
  Please be careful with older XCA versions.
  XCA before 1.4.0 will overwrite the new SQLite database during database open.


Dowload
-------

The most recent stable version of XCA can be downloaded from
http://hohnstaedt.de/xca/index.php/download

The current (unstable) HEAD of development can be downloaded and tested via
https://github.com/chris2511/xca/

Please do not hesitate to contact me for information about branches.

DH Parameters
--------------

Diffie Hellman parameters can be created by XCA.
It does neither need nor use the parameters.
Applications like OpenVPN however need them and so XCA provides this
functionality for users convenience.

Entropy sources for XCA
-----------------------

Entropy is a very important topic for key generation.
OpenSSL comes with a good pseudo random number generator.
XCA seeds it very thoroughly.

  1) During startup

     - The OpenSSL seeding mechanism `RAND_poll()`. It uses */dev/urandom*
       where possible and the screen content on Windows.
     - XCA also tries to pull at most 256bit from */dev/random* and
       */dev/hwrng* each.
     - A *.rnd* state file in the XCA application directory is
       read on startup and erased afterwards to avoid replays.

  2) Before any key or parameter generation a "re-seeding" is done.
     Some say re-seeding is not necessary, but all say it does not harm.

     - XCA collects entropy by mouse and keyboard events and its timing.
       `XcaApplication.cpp: bool XcaApplication::eventFilter()`
       We are on a desktop host after all.
     - 256bit from */dev/urandom* (unix/Mac)

  3) A *.rnd* state file in the XCA application directory
     is written whenever XCA finishes.

  4) When managing a token or generating a key on a token that supports
     `C_GenerateRandom` and `C_SeedRandom`, XCA will:

     - Seed the token with own random data.
     - Seed the OpenSSL CSPRNG by random bytes from the token.
