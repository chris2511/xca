
Templates
=========

Templates are special to XCA and not interchangeable with other applications.
They store all information to create certificates or requests.

To use templates, just create a new certificate or request and apply one
of the templates (or parts of it) in the *Source* Tab.
Usually you have the distinguished name parts, that never change and
properties (extensions) that define the use of the certificate.
You may apply the whole template or only the subject or only the extensions.

Next to the 3 default templates for CA, TLS server and client
certificates, customized templates may be created. Templates are not signed,
they are just a collection of common values for different certificates.
Therefore XCA does not care if any duplicates exist in the list of templates.

An easy way to create templates is to export an existing certificate or
PKCS#10 request to a template. Just select *Transform->Template*
in the context-menu of the item. The private key of the
Certificate or Request is not required for this operation.
