
list(APPEND xcadoc_sources arguments.cpp arguments.h xcadoc.cpp)

list(APPEND xca_sources
BioByteArray.cpp	dbhistory.cpp		pki_key.cpp
BioByteArray.h		dbhistory.h		pki_key.h
Passwd.cpp		entropy.cpp		pki_lookup.h
Passwd.h		entropy.h		pki_multi.cpp
arguments.cpp		exception.h		pki_multi.h
arguments.h		func.cpp		pki_pkcs12.cpp
asn1int.cpp		func.h			pki_pkcs12.h
asn1int.h		headerlist.h		pki_pkcs7.cpp
asn1time.cpp		ipvalidator.h		pki_pkcs7.h
asn1time.h		load_obj.cpp		pki_scard.cpp
base.h			load_obj.h		pki_scard.h
builtin_curves.cpp	main.cpp		pki_temp.cpp
builtin_curves.h	main.h			pki_temp.h
database_model.cpp	oid.cpp			pki_x509.cpp
database_model.h	oid.h			pki_x509.h
db_base.cpp		opensc-pkcs11.h		pki_x509req.cpp
db_base.h		openssl_compat.h	pki_x509req.h
db_crl.cpp		pass_info.cpp		pki_x509super.cpp
db_crl.h		pass_info.h		pki_x509super.h
db_key.cpp		pk11_attribute.cpp	settings.cpp
db_key.h		pk11_attribute.h	settings.h
db_temp.cpp		pkcs11.cpp		sql.cpp
db_temp.h		pkcs11.h		sql.h
db_token.cpp		pkcs11_lib.cpp		version.cpp
db_token.h		pkcs11_lib.h		x509name.cpp
db_x509.cpp		pki_base.cpp		x509name.h
db_x509.h		pki_base.h		x509rev.cpp
db_x509req.cpp		pki_crl.cpp		x509rev.h
db_x509req.h		pki_crl.h		x509v3ext.cpp
db_x509super.cpp	pki_evp.cpp		x509v3ext.h
db_x509super.h		pki_evp.h		xfile.h
dhgen.cpp		dhgen.h			XcaProgress.cpp
XcaProgress.h		XcaWarningCore.cpp	XcaWarningCore.h
PwDialogCore.cpp	PwDialogCore.h		digest.h
digest.cpp		pki_export.cpp
)

list(TRANSFORM xca_sources PREPEND ${PROJECT_SOURCE_DIR}/lib/)
list(TRANSFORM xcadoc_sources PREPEND ${PROJECT_SOURCE_DIR}/lib/)

list(APPEND xca_sources ${PROJECT_BINARY_DIR}/local.h)
list(APPEND xcadoc_sources ${PROJECT_BINARY_DIR}/local.h)

target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${xca_sources})
target_sources(xcadoc PRIVATE ${xcadoc_sources})
