
TEMPLATE = app
TARGET = xca
DEPENDPATH += . lang lib ui widgets
INCLUDEPATH += . lib widgets
QMAKE_MAKEFILE = makefile
QT = gui core sql widgets
QT += help

RESOURCES = img/imgres.rcc
RC_FILE = img/w32res.rc

macx {
	ICON = img/xca-mac-icon.icns
	CONFIG += release_and_debug
	XCA_RESOURCES.files = misc/oids.txt misc/dn.txt misc/eku.txt
	XCA_RESOURCES.files += misc/CA.xca misc/TLS_client.xca misc/TLS_server.xca
	XCA_RESOURCES.files += lang/xca_de.qm lang/xca_es.qm lang/xca_ru.qm lang/xca_fr.qm
	XCA_RESOURCES.files += lang/xca_hr.qm lang/xca_it.ts lang/xca_ja.ts lang/xca_nl.ts
	XCA_RESOURCES.files += lang/xca_pl.ts lang/xca_sk.ts lang/xca_tr.ts
	XCA_RESOURCES.files += lang/xca_zh_CN.ts lang/xca_pt_BR.ts
	XCA_RESOURCES.path = Contents/Resources
	QMAKE_BUNDLE_DATA += XCA_RESOURCES
}

LIBS += -lcrypto -lltdl
QMAKE_CXXFLAGS = -Werror -DQMAKE
DEFINES += XCA_VERSION=\\\"'$$system(cat VERSION)'\\\"

!win32 {
  commithash.h.commands = ./gen_commithash.h.sh \$@
  commithash.h.depends = FORCE
  QMAKE_EXTRA_TARGETS += commithash.h
}
win32 {
  DEFINES += NO_COMMITHASH
}

# Input
HEADERS += lib/asn1int.h \
           lib/asn1time.h \
           lib/base.h \
           lib/db_base.h \
           lib/db_crl.h \
           lib/db.h \
           lib/db_key.h \
           lib/db_temp.h \
           lib/db_token.h \
           lib/db_x509.h \
           lib/db_x509req.h \
           lib/db_x509super.h \
           lib/exception.h \
           lib/func.h \
           lib/headerlist.h \
           lib/load_obj.h \
           lib/main.h \
           lib/oid.h \
           lib/opensc-pkcs11.h \
           lib/pass_info.h \
           lib/Passwd.h \
           lib/pk11_attribute.h \
           lib/pkcs11.h \
           lib/pkcs11_lib.h \
           lib/pki_base.h \
           lib/pki_crl.h \
           lib/pki_evp.h \
           lib/pki_key.h \
           lib/pki_multi.h \
           lib/pki_pkcs12.h \
           lib/pki_pkcs7.h \
           lib/pki_scard.h \
           lib/pki_temp.h \
           lib/pki_x509.h \
           lib/pki_x509req.h \
           lib/pki_x509super.h \
           lib/x509name.h \
           lib/x509rev.h \
           lib/x509v3ext.h \
           lib/builtin_curves.h \
           lib/entropy.h \
           lib/settings.h \
           lib/sql.h \
           lib/database_model.h \
           lib/arguments.h \
           lib/BioByteArray.h \
           lib/dbhistory.h \
           widgets/CertDetail.h \
           widgets/CertExtend.h \
           widgets/clicklabel.h \
           widgets/CrlDetail.h \
           widgets/distname.h \
           widgets/ExportDialog.h \
           widgets/hashBox.h \
           widgets/ImportMulti.h \
           widgets/KeyDetail.h \
           widgets/kvView.h \
           widgets/MainWindow.h \
           widgets/NewCrl.h \
           widgets/NewKey.h \
           widgets/NewX509.h \
           widgets/Options.h \
           widgets/PwDialog.h \
           widgets/v3ext.h \
           widgets/validity.h \
           widgets/SearchPkcs11.h \
           widgets/RevocationList.h \
           widgets/XcaTreeView.h \
           widgets/CertTreeView.h \
           widgets/KeyTreeView.h \
           widgets/ReqTreeView.h \
           widgets/TempTreeView.h \
           widgets/CrlTreeView.h \
           widgets/X509SuperTreeView.h \
           widgets/XcaHeaderView.h \
           widgets/OidResolver.h \
           widgets/ItemCombo.h \
           widgets/XcaDialog.h \
           widgets/XcaProxyModel.h \
           widgets/XcaApplication.h \
           widgets/XcaWarning.h \
           widgets/Help.h \
           widgets/OpenDb.h

FORMS += ui/CaProperties.ui \
         ui/CertDetail.ui \
         ui/CertExtend.ui \
         ui/CrlDetail.ui \
         ui/ExportDialog.ui \
         ui/Help.ui \
         ui/ImportMulti.ui \
         ui/KeyDetail.ui \
         ui/MainWindow.ui \
         ui/NewCrl.ui \
         ui/NewKey.ui \
         ui/NewX509.ui \
         ui/Options.ui \
         ui/PwDialog.ui \
         ui/Revoke.ui \
         ui/SelectToken.ui \
         ui/SearchPkcs11.ui \
         ui/v3ext.ui \
         ui/OidResolver.ui \
         ui/XcaDialog.ui \
         ui/RevocationList.ui \
         ui/OpenDb.ui \
         ui/ItemProperties.ui

SOURCES += lib/asn1int.cpp \
           lib/asn1time.cpp \
           lib/db_base.cpp \
           lib/db.cpp \
           lib/db_crl.cpp \
           lib/db_key.cpp \
           lib/db_temp.cpp \
           lib/db_token.cpp \
           lib/db_x509.cpp \
           lib/db_x509req.cpp \
           lib/db_x509super.cpp \
           lib/func.cpp \
           lib/load_obj.cpp \
           lib/main.cpp \
           lib/oid.cpp \
           lib/pass_info.cpp \
           lib/Passwd.cpp \
           lib/pk11_attribute.cpp \
           lib/pkcs11.cpp \
           lib/pkcs11_lib.cpp \
           lib/pki_base.cpp \
           lib/pki_crl.cpp \
           lib/pki_evp.cpp \
           lib/pki_key.cpp \
           lib/pki_multi.cpp \
           lib/pki_pkcs12.cpp \
           lib/pki_pkcs7.cpp \
           lib/pki_scard.cpp \
           lib/pki_temp.cpp \
           lib/pki_x509.cpp \
           lib/pki_x509req.cpp \
           lib/pki_x509super.cpp \
           lib/x509name.cpp \
           lib/x509rev.cpp \
           lib/x509v3ext.cpp \
           lib/builtin_curves.cpp \
           lib/entropy.cpp \
           lib/settings.cpp \
           lib/version.cpp \
           lib/sql.cpp \
           lib/database_model.cpp \
           lib/arguments.cpp \
           lib/BioByteArray.cpp \
           lib/dbhistory.cpp \
           widgets/CertDetail.cpp \
           widgets/CertExtend.cpp \
           widgets/clicklabel.cpp \
           widgets/CrlDetail.cpp \
           widgets/distname.cpp \
           widgets/ExportDialog.cpp \
           widgets/hashBox.cpp \
           widgets/ImportMulti.cpp \
           widgets/KeyDetail.cpp \
           widgets/kvView.cpp \
           widgets/MainWindow.cpp \
           widgets/MW_help.cpp \
           widgets/MW_menu.cpp \
           widgets/NewCrl.cpp \
           widgets/NewKey.cpp \
           widgets/NewX509.cpp \
           widgets/NewX509_ext.cpp \
           widgets/Options.cpp \
           widgets/PwDialog.cpp \
           widgets/v3ext.cpp \
           widgets/validity.cpp \
           widgets/SearchPkcs11.cpp \
           widgets/RevocationList.cpp \
           widgets/XcaTreeView.cpp \
           widgets/CertTreeView.cpp \
           widgets/KeyTreeView.cpp \
           widgets/ReqTreeView.cpp \
           widgets/TempTreeView.cpp \
           widgets/CrlTreeView.cpp \
           widgets/X509SuperTreeView.cpp \
           widgets/XcaHeaderView.cpp \
           widgets/OidResolver.cpp \
           widgets/XcaProxyModel.cpp \
           widgets/XcaApplication.cpp \
           widgets/XcaWarning.cpp \
           widgets/Help.cpp \
           widgets/OpenDb.cpp

TRANSLATIONS += lang/xca.ts \
		lang/xca_de.ts \
		lang/xca_es.ts \
		lang/xca_fr.ts \
		lang/xca_hr.ts \
		lang/xca_it.ts \
		lang/xca_ja.ts \
		lang/xca_nl.ts \
		lang/xca_pl.ts \
		lang/xca_pt_BR.ts \
		lang/xca_ru.ts \
		lang/xca_sk.ts \
		lang/xca_tr.ts \
		lang/xca_zh_CN.ts \
