
TEMPLATE = app
TARGET = xca
DEPENDPATH += . lang lib ui widgets
INCLUDEPATH += . lib widgets

RESOURCES = img/imgres.rcc
RC_FILE = img/w32res.rc

macx {
	ICON = img/xca-mac-icon.icns
	CONFIG += release_and_debug
	XCA_RESOURCES.files = misc/oids.txt misc/aia.txt misc/CA.xca misc/dn.txt misc/eku.txt misc/HTTPS_client.xca misc/HTTPS_server.xca
	XCA_RESOURCES.files += lang/xca_de.qm lang/xca_es.qm
	XCA_RESOURCES.path = Contents/Resources
	QMAKE_BUNDLE_DATA += XCA_RESOURCES
}

LIBS += -lcrypto -lltdl

# Input
HEADERS += local.h \
           lib/asn1int.h \
           lib/asn1time.h \
           lib/base.h \
           lib/db.h \
           lib/db_base.h \
           lib/db_crl.h \
           lib/db_key.h \
           lib/db_temp.h \
           lib/db_x509.h \
           lib/db_x509req.h \
           lib/db_x509super.h \
           lib/exception.h \
           lib/func.h \
           lib/load_obj.h \
           lib/oid.h \
           lib/pass_info.h \
           lib/pki_base.h \
           lib/pki_crl.h \
           lib/pki_key.h \
           lib/pki_pkcs12.h \
           lib/pki_pkcs7.h \
           lib/pki_temp.h \
           lib/pki_x509.h \
           lib/pki_x509req.h \
           lib/pki_x509super.h \
           lib/pki_multi.h \
           lib/x509name.h \
           lib/x509rev.h \
           lib/x509v3ext.h \
           lib/opensc-pkcs11.h \
           lib/pk11_attribute.h \
           lib/pki_evp.h \
           lib/pki_scard.h \
           widgets/CertDetail.h \
           widgets/CertExtend.h \
           widgets/clicklabel.h \
           widgets/CrlDetail.h \
           widgets/distname.h \
           widgets/ExportCert.h \
           widgets/ExportDer.h \
           widgets/ExportKey.h \
           widgets/hashBox.h \
           widgets/ImportMulti.h \
           widgets/KeyDetail.h \
           widgets/MainWindow.h \
           widgets/NewX509.h \
	   widgets/Options.h \
           widgets/ReqDetail.h \
           widgets/v3ext.h \
           widgets/validity.h \
           widgets/NewKey.h \
           widgets/XcaTreeView.h
FORMS += ui/About.ui \
         ui/CaProperties.ui \
         ui/CertDetail.ui \
         ui/CertExtend.ui \
         ui/CrlDetail.ui \
         ui/ExportCert.ui \
         ui/ExportDer.ui \
         ui/ExportKey.ui \
         ui/Help.ui \
         ui/ImportMulti.ui \
         ui/KeyDetail.ui \
         ui/MainWindow.ui \
         ui/NewCrl.ui \
         ui/NewKey.ui \
         ui/NewX509.ui \
         ui/Options.ui \
         ui/PassRead.ui \
         ui/PassWrite.ui \
         ui/ReqDetail.ui \
         ui/TrustState.ui \
         ui/v3ext.ui
SOURCES += lib/asn1int.cpp \
           lib/asn1time.cpp \
           lib/db.cpp \
           lib/db_base.cpp \
           lib/db_crl.cpp \
           lib/db_key.cpp \
           lib/db_temp.cpp \
           lib/db_x509.cpp \
           lib/db_x509req.cpp \
           lib/db_x509super.cpp \
           lib/func.cpp \
           lib/import.cpp \
           lib/load_obj.cpp \
           lib/main.cpp \
           lib/oid.cpp \
           lib/pki_base.cpp \
           lib/pki_crl.cpp \
           lib/pki_key.cpp \
           lib/pki_pkcs12.cpp \
           lib/pki_pkcs7.cpp \
           lib/pki_temp.cpp \
           lib/pki_x509.cpp \
           lib/pki_x509req.cpp \
           lib/pki_x509super.cpp \
           lib/pki_multi.cpp \
           lib/x509name.cpp \
           lib/x509rev.cpp \
           lib/x509v3ext.cpp \
           lib/pk11_attribute.cpp \
           lib/pkcs11.cpp \
           lib/pki_evp.cpp \
           lib/pki_scard.cpp \
           widgets/NewKey.cpp \
           widgets/CertDetail.cpp \
           widgets/CertExtend.cpp \
           widgets/clicklabel.cpp \
           widgets/CrlDetail.cpp \
           widgets/distname.cpp \
           widgets/ExportCert.cpp \
           widgets/ExportDer.cpp \
           widgets/ExportKey.cpp \
           widgets/hashBox.cpp \
           widgets/ImportMulti.cpp \
           widgets/KeyDetail.cpp \
           widgets/MainWindow.cpp \
           widgets/MW_database.cpp \
           widgets/MW_help.cpp \
           widgets/NewX509.cpp \
           widgets/NewX509_ext.cpp \
	   widgets/Options.cpp \
           widgets/ReqDetail.cpp \
           widgets/v3ext.cpp \
           widgets/validity.cpp \
           widgets/XcaTreeView.cpp \
           widgets/MW_menu.cpp
TRANSLATIONS += lang/xca_de.ts lang/xca_es.ts
