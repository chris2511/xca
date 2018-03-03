# XCA -- X Certificate and Key Management

## __Release Notes__

 * Make a backup copy of your database!
 * Send bugs to christian@hohnstaedt.de

## __Changelog:__

### xca 1.4.1

 * Replace links to XCA on Sourceforge in the software and
   documentation by links to my Site.

*xca 1.4.1-pre02*

 * SF Bug #122 isValid() tried to convert the serial to 64 bit
 * Beautify mandatory distinguished name entry errors
 * Support dragging certificates and other items as PEM text
 * Show User settings and installation path in the about dialog

*xca 1.4.1-pre01*

 * Remove SPKAC support. Netscape is not of this world anymore.
 * SF bug #124 Wrong assumptions about slots returned by PKCS11 library
 * Cleanup and improve the OID text files, remove senseless aia.txt
 * Update HTML documentation
 * Refine and document Entropy gathering
 * Indicate development and release version by git commit hash
 * Fix dumping private keys during "Dump database"
 * Fix Null pointer exception when importing PKCS#12 with OpenSSL 1.1.0
 * SF Bug #110 Exported private key from 4096 bit SSH key is wrong
 * SF Bug #109 Revoked.png isn't a valid image
 * SF Bug #121 CA serial number is ignored in hierarchical view
 * Improve speed of Bulk import.
 * Fix starting xca with a database as first arg

### xca 1.4.0

 * Update OpenSSL version for MacOSX and W32 to 1.1.0g
 * Change default hash to SHA-256 and
   add a warning if the default hash algorithm is SHA1 or less
 * Switch to Qt5 for Windows build and installation
 * Do not apply the default template when creating a similar cert
 * Close SF #120 Crash when importing CA certificate
 * Close SF #116 db\_x509.cpp:521: Mismatching allocation and deallocation
 * Add support for OpenSSL 1.1 (by Patrick Monnerat)
 * Support generating an OpenSSL "index.txt" (by Adam Dawidowski)
 * Thales nCipher key generation changes for EC and DSA keys
 * Add Slovak translation
