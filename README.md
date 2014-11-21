# XCA -- X Certificate and Key Management

## __Release Notes__

 * Make a backup copy of your database!

 * The "1.1.0-brainpool" binaries of this release contain the ECC Brainpool
   curves (RFC5639) as an OpenSSL patch backported from OpenSSL 1.0.2-beta3
   (The patch can be found in the misc/ directory of the sources)

 * Send bugs to christian@hohnstaedt.de

## __Changelog:__

### xca 1.1.0

 * SF Bug #79 Template export from WinXP
   cannot be imported in Linux and Mac OS X
 * Support for Brainpool windows and MacOSX binaries
 * SF Feat. Req. #70 ability to search certificates
 * SF Feat. Req. #75 show SHA-256 digest
 * RedHat Bug #1164340 - segfault when viewing a
   RHEL entitlement certificate
 * Database hardening
   - Delete invalid items (on demand)
   - Be more tolerant against database errors
   - Gracefully handle and repair corrupt databases
   - Add "xca\_db\_stat(.exe)" binary to all installations
 * Translation updates
 * Optionally allow hash algos not supported by the token
 * Select whether to translate established x509 terms
 * Finish Token EC and DSA support - generate, import, export, sign
 * SF Feat. Req. #57 More options for Distinguished Name
 * Switch to autoconf for the configure script
 * SF Feature Req. #76 Export private keys to clipboard
 * EC Keys: show Curve name in table
 * Support EC key generation on PKCS#11 token
 * PKCS#11: Make EC and RSA signatures work
 * PKCS#11: Fix reading EC keys from card
 * SF Bug #82 Certificate Creation out of Spec
 * SF Bug #95 XCA 1.0 only runs in French on a UK English Mac


