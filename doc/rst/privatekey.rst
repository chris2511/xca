
.. index:: keydetail (keydetail)

.. _keys:

RSA, DSA and EC Keys
====================

For creating certificates, keys are needed.
All keys are stored encrypted in the database using the PKCS#8 AES algorithm.
The password can be changed for each key.

.. index:: keytab (keytab)

The password type means:

common:
  The database password provided during database load.
private:
  The key is encrypted with an individual passphrase, which is not stored
  by XCA. This can be set and reset via the context menu of the key.
PIN:
  Security tokens are usually protected by a PIN.
No password:
  Public keys don't need a password.

All keys carry a use counter which counts the times it is used in requests
or certificates. When creating new requests or certificates the list of
available keys is reduced to the keys with a use counter of 0.
This can be overridden by the check-box next to the key list.
Keys should *never* be used multiple times.

When importing an EC key with explicit curve parameters,
the corresponding curve OID is searched and set if found.

- Private Key columns

  - **Type**
    One of *RSA*, *DSA*, *EC*, *ED25519*.
  - **Size**
    Key size in bits.
  - **EC Group**
    Curve name of the EC key.
  - **Use**
    Number of certificates and requests in the database using this key.
    For new certificates and requests only unused or newly generated keys
    should be used.
  - **Password**
    Protection of the key. See :ref:`keys`

.. index:: keygen (keygen)

Generating Keys
---------------

The dialog asks for the internal name of the key and the key-size in bits.
For EC keys, a list of curves is shown.
It contains all X9.62 curves and many others.
For ED25519 keys no further information is required.

Even if the size drop-down list only shows the most usual key sizes,
any other size may be set here by editing this box.
While searching for random prime numbers a progress bar is shown in the
bottom of the base application.
After the key generation is done the key will be stored in the database.

When checking the *Remember as default* box, the settings
(Key-type, key-size or EC curve) will be remembered and preset for the
next key generation dialog. This option is not available
when generating keys on 'ref'`token`.

For every connected token providing the Key-Generate facility, an entry in the
drop-down menu of the key-types will be shown.
It contains the name of the token and the valid key-sizes.

In case of EC keys generated on a token, the list of possible curves
is restricted based on information provided by the token (Key size and FP/F2M).
The token may support even less ECParameters / OIDs. When selecting an
unsupported EC curve an error will occur.
Please consult the documentation of the provider of the PKCS#11 library.

.. index:: keyexport (keyexport)

Key Export
----------

Keys can be exported by either selecting the key and pressing *Export*
or by using the context-menu.

- **Clipboard:** Export the private or public key to the clipboard
- **Clipboard format:** The format for the clipboard-export can be selected as follows:

.. include:: export-key-clp.rst

- **File:** Export to external file.
  The filename can be selected in the export dialog and the Export format:

.. include:: export-key.rst

The filename is the internal name plus a *pem*, *der*, *pk8*, *pub* or *priv*
suffix.  When changing the file-format, the suffix of the filename changes
accordingly.  Only PKCS#8 or PEM files can be encrypted, because
the DER format (although it could be encrypted) does not support a way
to supply the encryption algorithm like e.g. *DES*.
Of course, encryption does not make sense if the private part is not exported.

When exporting the key via SQL from the database, see :ref:`extracting-items`
openssl asks for the password, which is either the database password or
its own password in case the password type is *private*.
