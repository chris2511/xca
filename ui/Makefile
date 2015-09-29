
ifeq ($(TOPDIR),)
TOPDIR=..
BUILD=..
endif

UI_H = ui_About.h ui_CaProperties.h ui_CertDetail.h ui_CertExtend.h \
	ui_CrlDetail.h ui_ExportDialog.h ui_Help.h \
	ui_ImportMulti.h ui_KeyDetail.h ui_MainWindow.h ui_NewCrl.h \
	ui_NewKey.h ui_NewX509.h ui_Options.h ui_PwDialog.h ui_Revoke.h \
	ui_SelectToken.h ui_TrustState.h ui_v3ext.h ui_SearchPkcs11.h \
	ui_RevocationList.h ui_OidResolver.h

include $(TOPDIR)/Rules.mak

ui: $(UI_H)
