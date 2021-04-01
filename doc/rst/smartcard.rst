
.. _token:

Smart-cards
===========

Since XCA 0.8.0 the use of Smart-cards (Security tokens) is supported.
It is based on the PKCS#11 standard. The Options dialog contains a list
to add one or more PKCS#11 providers (libraries).
This is not restricted to Smart-cards but includes all type of
security tokens like USB tokens.

Up to version 1.0.0 only RSA keys on security tokens were supported.
Since version 1.1.0 XCA also supports EC and DSA private keys
on security tokens.

Once again: This software comes with no warranty at all!
If XCA transforms your security token into a fridge, don't blame me.
For me everything worked fine and I tested it thoroughly.

On Linux the package *opensc* should be installed.
Please read the opensc documentation for more details.
Generally: if the opensc command-line-tool *pkcs11-tool -L*
shows reasonable output, XCA will work. Otherwise fix the opensc setup.

I had a functional setup with a "Reiner SCT" and a DELL keyboard
with integrated card reader and TCOS Netkey E4 cards.

I also used Aladdin Etoken very successfully (Thanks for support!).
The Aladdin PKCS#11 library supports all needed features very well.

The ECC token support was tested with the https://www.cardcontact.de
ECC tokens.
The OpenDNSSEC SoftHSMv2 was used as PKCS#11 reference implementation
to test all the token algorithms and certificate and key download
functionality to the token.

Before the keys of a token can be used, they must be imported into XCA.
This means that XCA reads the token and shows the keys and certificates
on the token. They can then be imported partially or completely
via the Multi-import dialog to be used by XCA.
It is not unusual that a token contains more than one key or certificate.
It is of course possible to create your own keys on the token.
When selecting a token-key for signing, XCA verifies that the
corresponding token is available.

If the Card reader supports a secure PIN input by a built-in keyboard,
it will be used by XCA and it will not ask for the PIN but waits for
the Pin-pad input.

The following actions with smart-cards are supported:

- Import keys and certificates from the token. (Token->Manage Security token)
- Everything you can do with other keys can be done with tokens, too.
- On export, only the Public key is exported.
- Change the PIN and SO PIN of a token.
- Create a key on the token. (Button New Key)
- Store an existing key or certificate on the token. (Context menu of the item)
- Delete certificates and keys from the token. (Context menu of the item)
- Initialize cards and the user PIN via SO PIN

Existing, non-deletable, built-in certificates of Smart-cards may be ignored.
A new CA certificate can be created and self-signed by the Smart-card key.
It can then be used to issue end-entity certificates,
containing other RSA, DSA or EC keys, sign imported certificate requests
or generate CRLs.

Key Management on the Token
---------------------------

XCA assumes for every private key on the card a corresponding public key.
When managing cards, XCA only searches for public keys.
There is thus no need to enter a PIN. When using the the key for signing the
corresponding private key on the card is selected and a PIN must be entered.

Accordingly, every time a key is generated on the card,
a public/private key-pair is generated.
Every time a key is stored on the card, XCA creates a public
and a private key object.

Firefox always only looks for private keys on the card.
If XCA does not show a key, which is however recognized by Firefox
a missing public-key object is the cause.

The Token Menu
---------------

The menu item: *Token* is accessible if a PKCS#11 library was loaded and initialized.

Managing Smart-cards
....................

Security token specific operations are collected below
the menu-item *Token*

Manage Security Token
'''''''''''''''''''''

This is the Multi import dialog, which allows to view and select the items
to be imported. When started it reads the content of the selected token.
Additionally, it shows token information in the bottom-right corner and
allows to delete and rename items directly on the token.

Initializing Tokens
'''''''''''''''''''

Initializing tokens is done via the menu item *Initialize token*.
During this process either a new SO PIN must be supplied or the old
SO PIN must be given. Additionally XCA asks for the label of this token.

After this operation succeeded, the User PIN is uninitialized and must be
initialized via *Init PIN*

Deleting Items from the Token
'''''''''''''''''''''''''''''

Just delete the item as usual. XCA will then ask whether the item shall
also be removed from the token. Items on the token that were not yet
imported can be deleted via the "Manage security token" menu.

Changing PINs
'''''''''''''

The User PIN and SO PIN can be changed via the *Token* menu and also via the key context-menu. In this case the correct token containing the key will be enforced.

Tested Providers
................

The following providers were used for testing:

1) OpenSC: default provider for a lot of different cards and
   readers. Deleting keys or certificates is currently not supported.

   - The support of Netkey 4E cards is currently restricted.
     Only import and using the keys and certificates is possible.
   - Feitian PKI cards work with the following restrictions:

     - The cards must be initialized outside XCA with *pkcs15-init*
     - Storing keys onto the card crashes because of
       *assert(0)* in card-entersafe.c in opensc-0.11.13
     - Deleting items does not work, because it is not
       implemented in opensc-0.11.13/card-entersafe.c.

2) Aladdin eToken PKIclient-5.1: Works perfectly.
   Read public keys from the token, write private keys to the
   token, generate keys on the token, write certificates to the
   token and delete them from the token.

   - Linux only: OpenCryptoki (IBM): may be used as a pure software
     token, but also supports TPMs and other IBM crypto processors
   - https://www.cardcontact.de OpenSC branch supports RSA and EC Keys.
     Downloading keys to the token is not supported.
   - OpenDNSSEC SoftHSMv2 supports all mechanisms in software.
     A great reference to test the PKCS#11 library interface.

Tested compatibility with other applications
............................................

For interoperability tests I used the Aladdin eToken together with the
Aladdin PKIclient 5.1 software and OpenSC with the Feitian PKI-card.

- Aladdin: /usr/lib/libeTPkcs11.so
- Feitian: /usr/lib/opensc-pkcs11.so (default)

I initialized the token as follows:

- Generate CA certificate with software key
- Generate server certificate with software key
- Generate client certificate with a key generated on the token
- Generate 2nd client certificate with software key
- Copy the software-key of the 2nd client certificate onto the token
- Copy the 2 client certificates onto the token
- Export CA certificate as PEM (ca.crt)
- Export server cert as PKCS12 without password (server.p12)
- Export server cert as "PEM Cert + key" without password
  (server.pem) for Apache2

Firefox / Mozilla -> Apache
...........................

- Enable PKCS#11 token in Firefox:

  - *Edit->Preferences->Advanced:*
    (Security Devices): (Load) Load PKCS#11 Device: /usr/lib/libeTPkcs11.so
  - Import CA certificate: *Edit->Preferences->Advanced:*
    (View Certificates) (Authorities): (Import)

- Prepare apache config with:

  .. code-block:: apache

    SSLEngine on
    SSLCertificateFile      /etc/apache2/ssl/server.pem
    SSLCertificateKeyFile   /etc/apache2/ssl/server.pem
    SSLCertificateChainFile /etc/apache2/ssl/ca.crt
    SSLCACertificateFile    /etc/apache2/ssl/ca.crt
    SSLVerifyClient         require
    SSLVerifyDepth          10

- Connect with Firefox to the server. Firefox will prompt you
  to select one of the 2 client certificates. Both work.

OpenVPN
.......

The relevant server config is as follows:

.. code-block:: apache

  pkcs12 server.p12

The client config is:

.. code-block:: apache

  ca ca.crt
  pkcs11-providers /usr/lib/libeTPkcs11.so
  pkcs11-id 'Aladdin\x20Knowledge\x20Systems\x20Ltd\x2E/eToken/002882d2/F\xC3\xBCr\x20den\x20Firefox/D1A7BFF94B86C061'

The pkcs11-id can be obtained with the command:

.. code-block:: bash

  $ openvpn --show-pkcs11-ids /usr/lib/libeTPkcs11.so

