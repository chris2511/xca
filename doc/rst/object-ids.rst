
.. _objectids:

Object IDs
==========

Private Object IDs and OID lists for the distinguished name or extended key
usage can be added in files listed below.
The files are:

- **oids.txt:** additional Object IDs
- **eku.txt:** Content of *ExtendedKeyUsage*
- **dn.txt:** Content of *DistinguishedName*

The search path for all the files is listed below.
All files except *oids.txt* are searched in the order listed below
and search stops at the first file found.
The *oids.txt* file is searched in reversed order and all
*oids.txt* files found are loaded.

- Unix

  - $HOME/.xca/
  - /etc/xca/
  - PREFIX/share/xca/ <newline>PREFIX is usually /usr or /usr/local

- Windows

  - CSIDL_APPDATA\xca, which is something like

    C:\Documents and Settings\username\Application Data\xca
    or C:\Users\username\AppData\Roaming\xca
  - Installation directory
    e.g.: `C:\Programs\xca`

- MacOSX

  - $HOME/Library/Application Support/data/xca
  - /Applications/xca.app/Resources

The path of the user settings directory depends on the
operating system and version.
The path where XCA looks for this file is shown in the
*About* dialog of XCA as *User settings path*.

.. _new_oids:

New OIDs
--------

All Object IDs that are not official, but belong to your company
or organisation can be added in the file *oids.txt*.
All possible locations for this file are searched and all *oids.txt* files
found are loaded. This way the application-installer adds
some in */usr/share/xca*, the Administrator in */etc/xca* and the user in
*$HOME/.xca*. The format of this file is:<newline>
*OID*:*shortname*:*longname*
Leading and trailing spaces between the colons and the text are ignored.
Lines starting with a *#* are ignored.

OID lists
---------

The files containing OID lists (*eku.txt, dn.txt*)
are handled in a different way, only the first one found is used.
The format of this files is one entry per line. The entry can be either the
numerical OID like *1.3.6.1.5.5.8.2.2*, the short name like
*iKEIntermediate* or the long name *IP security end entity*.
Lines starting with a *#* are ignored.
If this files shall contain new in-official OIDs, they must be also mentioned
in one of the *oids.txt* files.

Configure Subject entries
-------------------------

If you want to / need to add your own company specific subject
entry to your certificate it can be done without recompiling XCA.

1) Add its OID with short name and long name to one
   of the *oids.txt* file listed in :ref:`new_oids` like:
   *1.3.6.1.4.1.12345.1: zodiacSign: Zodiac Sign*
2) Add the OID, short name or long name to the first read *dn.txt*
   On Linux: `cp /usr/share/xca/dn.txt ~/.xca/dn.txt && echo "zodiacSign" >> ~/.xca/dn.txt`
3) Start XCA, open your database and goto *Options->Distinguished name*.
   In the *Explicit subject entries* select *Zodiac Sign*, click *Add*,
   move it by dragging it in the list and click OK when satisfied.
4) Create a new certificate and see.

