

Step by Step guides
===================

Beginners may follow these steps to easily create their first certificates.
This guide shows the minimal requirements for various tasks.  For more
advanced use of XCA, users are encouraged to familiarize themselves with
the applicable standards.

Setting up a Root CA Certificate
--------------------------------

1) Click the *Certificates* tab.
2) Click the *New Certificate* button.
3) Make sure the *Source* tab is showing, clicking it if necessary.

   - At the bottom of the panel, ensure that the *default CA* template
     is showing, and click the *Apply all* button. This will fill in
     appropriate values under the *Extensions*, *Key Usage*, and *Netscape*
     tabs.

4) Click the *Subject* tab.

   - Type in the internal name; this is for display purposes in the tool, only.
   - Fill in the required fields in the upper Distinguished Name section
     (Country name, State/Province, Locality, Organization, Common name,
     E-Mail address). The common name can be something like
     "ACME Certificate Authority".
   - If you want to add in any additional parts to the distinguished name,
     use the *Add* button.
   - Select the desired private key or generate a new one.

5) Click the *Extensions* tab.

   - The Time Range is probably fine (10 years). If you want to change the
     duration, then change it and click *Apply*.

6) The CRL distribution point will be part of the issued certificates.
   It should however be thought about a common URL for all of them like
   *http://www.example.com/crl/crl.der*
7) Click the *OK* button at the bottom.

You may wish to now issue an (initially) empty CRL.  Follow the instructions
given for issuing CRLs below, except that you do not actually revoke any
certificate.

Creating a CA-Signed Host Certificate
-------------------------------------

1) Click the *Certificates* tab.
2) Click the *New Certificate* button.
3) Make sure the *Source* tab is showing, clicking it if necessary.

   - At the bottom of the panel, select the template "(default) TLS_server"
     (or another suitable template, if you have created your own)
     and click the *Apply* button. This will fill in appropriate values
     under the *Extensions*, *Key Usage*, and *Netscape* tabs.
   - In the Signing section, select the certificate that will be used to
     sign the new certificate.

4) Click the *Subject* tab.

   - Type in the internal name; this is for display purposes in the tool,
     only. For host certificates, the host FQDN (fully qualified domain
     name) is not a bad choice.
   - Fill in the required fields in the upper "Distinguished Name" section
     (Country code, State/Province, Locality, Organization, Common name,
     E-Mail address). For host certificates, the common name must be the
     FQDN to which you wish users to connect. This need not be the canonical
     name of the host, but can also be an alias. For example, if
     *pluto.example.com* is your web server and it has a DNS CNAME entry of
     *www.example.com*, then you probably want the Common Name value in the
     certificate to be *www.example.com*.
   - If you want to add in any additional parts to the distinguished name,
     use the drop-down box and *Add* button.
   - Select the desired private key or generate a new one.

5) Click the *Extensions* tab.

   - Change the Time Range if desired and click *Apply*.
   - In the event that you need to revoke any certificates in the future,
     you should designate a certificate revocation list location. The
     location must be unique for this root certificate. XCA exports CRLs in
     either PEM or DER format with appropriate suffixes, so this should be
     considered when selecting the URL. Selecting a URI something like
     *http://www.example.com/crl/crl.der* is probably suitable.

     On the "CRL distribution point" line, click the *Edit* button. Type in
     the desired URI, then click *Add*. Add in any additional desired URIs
     in the same fashion. Click *Validate* and *Apply*. (Alternate mechanisms
     such as OCSP are beyond the scope of this guide.)

   - Click the OK button at the bottom

Creating a Self-Signed Host Certificate
---------------------------------------

This procedure is almost identical to that of creating a CA-Signed
certificate with the following exceptions:

1) When creating certificate, select "Create a self signed certificate"
   under the *Source* tab.
2) Self-signed certificates cannot be revoked, so the CRL URI should
   be blank.

Setting Up A Template
---------------------

If you have, or expect to have, multiple hosts under one domain and
signed by the same root certificate, then setting up a template for
your hosts can simplify host certificate creation and improve consistency.

The values of templates can be applied on the first tab of the
certificate-generation dialog. It can be selected, whether the subject,
the extensions or both parts of the template will be applied.
This way a subject-only template may be defined and later
applied together with the TLS_client or TLS_server template.

1) Click on the *Templates* tab.
2) Click on the *New Template* button
3) Select an appropriate value for the Preset Template Values, then click *OK*
4) Under the *Subject* tab, specify an internal name for the template.
5) Fill in (or modify) any values that you wish to be populated when using
   the template. Leave the rest blank (notably the "Common Name" field).
6) When all desired fields are filled in, click the *OK* button at the
   bottom of the window.

Your template is now ready for use when creating new certificates.

Alternatively, you may export an existing Certificate or Certificate
signing request to a template by the Export-context menu of the item.

Revoking a Certificate issued by a CA
-------------------------------------

1) Click the *Certificates* tab.
2) Right-click on the certificate that you want to revoke and select *Revoke*
3) Right-click the CA certificate that was used to sign the certificate
   being revoked. Select *CA* --> *Generate CRL*
4) Click the *OK* button in the *Create CRL* dialog.
5) Click on the *Revocation lists* tab in the main window.
6) Right-click on the CRL you just generated and select *Export*.
   Select the desired format (probably DER) and click *OK*
7) Copy the exported CRL to the location published in the issued
   certificate's CRL Distribution Points.
8) Optionally, delete older CRLs for the same CA certificate.

