..
  Automatically created by
  XCA_SPECIAL=rst ./xca > doc/rst/arguments.rst

--crlgen=ca-identifier    Generate CRL for <ca>. Use the \'name\' option to set the internal name of the new CRL. [#need-db]_
--database=database       File name (\*.xdb) of the SQLite database or a remote database descriptor\: [user\@host/TYPE\:dbname#prefix].
--exit                    Exit after importing items.
--help                    Print this help and exit.
--hierarchy=directory     Save OpenSSL index hierarchy in <dir>. [#need-db]_
--index=file              Save OpenSSL index in <file>. [#need-db]_
--import                  Import all provided items into the database. [#need-db]_
--issuers                 Print all known issuer certificates that have an associated private key and the CA basic constraints set to \'true\'. [#need-db]_
--keygen=type             Generate a new key and import it into the database. Use the \'name\' option to set the internal name of the new key. The <type> parameter has the format\: \'[RSA|DSA|EC]\:[<size>|<curve>]. [#need-db]_
--list-curves             Prints all known Elliptic Curves.
--name=internal-name      Provides the name of new generated items. An automatic name will be generated if omitted. [#need-db]_
--no-gui                  Do not start the GUI. Alternatively set environment variable XCA\_NO\_GUI=1 or call xca as \'xca-console\' symlink.
--password=password       Database password for unlocking the database.
--pem                     Print PEM representation of provided files. Prints only the public part of private keys.
--print                   Print a synopsis of provided files.
--sqlpass=password        Password to access the remote SQL server.
--text                    Print the content of provided files as OpenSSL does.
--verbose                 Print debug log on stderr. Alternatively set the environment variable XCA\_DEBUG=1.
--version                 Print version information and exit.


.. [#need-db] Requires a database. Either from the commandline or as default database.

Passphrase arguments
.....................
The password options accept the same syntax as openssl does:

env\:var
  Obtain the password from the environment variable var. Since the environment of other processes is visible on certain platforms (e.g. ps under certain Unix OSes) this option should be used with caution.
fd\:number
  Read the password from the file descriptor number. This can be used to send the data via a pipe for example.
file\:pathname
  The first line of pathname is the password. If the same pathname argument is supplied to password and sqlpassword arguments then the first line will be used for both passwords. pathname need not refer to a regular file\: it could for example refer to a device or named pipe.
pass\:password
  The actual password is password. Since the password is visible to utilities (like \'ps\' under Unix) this form should only be used where security is not important.
stdin
  Read the password from standard input.

