
ifeq ($(TOPDIR),)
TOPDIR=..
BUILD=..
endif

UI_H =  ui_CaProperties.h ui_CertDetail.h ui_CertExtend.h \
	ui_CrlDetail.h ui_ExportDialog.h ui_Help.h \
	ui_ImportMulti.h ui_KeyDetail.h ui_MainWindow.h ui_NewCrl.h \
	ui_NewKey.h ui_NewX509.h ui_Options.h ui_PwDialog.h ui_Revoke.h \
	ui_SelectToken.h ui_XcaDialog.h ui_v3ext.h ui_SearchPkcs11.h \
	ui_RevocationList.h ui_OidResolver.h ui_OpenDb.h ui_ItemProperties.h

include $(TOPDIR)/Rules.mak

ui all: $(UI_H)
