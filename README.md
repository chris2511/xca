# XCA -- X Certificate and Key Management

## __Release Notes__

 * Make a backup copy of your database!
 * Send bugs to christian@hohnstaedt.de

## __Changelog:__


### xca 1.3.2


 * Gentoo Bug #562288 linking fails
 * Add OID resolver, move some Menu items to "Extra"
 * SF. Bug. #81 Make xca qt5 compatible
 * SF. Bug. #107 error:0D0680A8:asn1 encoding
 * Don't validate notBefore and notAfter if they are disabled.


### xca 1.3.1


 * Fix endless loop while searching for a signer of a CRL


### xca 1.3.0


 * Update to OpenSSL 1.0.2d for Windows and MAC
 * SF Bug #105 1.2.0 OS X Retina Display Support
 * Digitaly sign Windows and MAC binaries with a valid certificate
 * Refactor the context menu. Exporting many selected items the clipboard or a PEM file now works. Certificate renewal and revocation now be performed on a batch of certificates.
 * Feat. Reg. #83 Option to revoke old certificate when renewing
 * Refactor revocation handling. All revocation information is with the CA and may be modified. certificates may now be deleted from the database
 * Support nameConstraints, policyMappings, InhibitAnyPolicy, PolicyConstraint (OSCP)noCheck when transforming certificates to templates or OpenSSL configs
 * Fix SF Bug #104 Export to template introduces spaces
 * Add option for disabling legacy Netscape extensions
 * Support exporting SSH2 public key to the clipboard
 * SF Bug #102 Weak entropy source used for key generation: /dev/random, mouse/kbd entropy, token RNG
 * SF Feat. Req. #80 Create new certificate, on existing certificate, same for requests
 * Add Cert/Req Column for Signature Algorithm
 * SF Feat. Req. #81 Show key size in New Certificate dialog
 * Distinguish export from transform: Export writes to an external file, Transform generates another XCA item

