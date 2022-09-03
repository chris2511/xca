list(APPEND xca_sources
CertDetail.cpp		NewCrl.cpp		XcaApplication.h
CertDetail.h		NewCrl.h		XcaDialog.cpp
CertExtend.cpp		NewKey.cpp		XcaDialog.h
CertExtend.h		NewKey.h		XcaHeaderView.cpp
CertTreeView.cpp	NewX509.cpp		XcaHeaderView.h
CertTreeView.h		NewX509.h
CrlDetail.cpp		NewX509_ext.cpp		XcaProxyModel.cpp
CrlDetail.h		OidResolver.cpp		XcaProxyModel.h
CrlTreeView.cpp		OidResolver.h		XcaTreeView.cpp
CrlTreeView.h		OpenDb.cpp		XcaTreeView.h
ExportDialog.cpp	OpenDb.h		XcaWarning.cpp
ExportDialog.h		Options.cpp		XcaWarning.h
FocusCombo.h		Options.h		clicklabel.cpp
Help.cpp		PwDialog.cpp		clicklabel.h
Help.h			PwDialog.h
ImportMulti.cpp		ReqTreeView.cpp
ImportMulti.h		ReqTreeView.h		distname.cpp
ItemCombo.h		RevocationList.cpp	distname.h
KeyDetail.cpp		RevocationList.h	hashBox.cpp
KeyDetail.h		SearchPkcs11.cpp	hashBox.h
KeyTreeView.cpp		SearchPkcs11.h		kvView.cpp
KeyTreeView.h		TempTreeView.cpp	kvView.h
MW_help.cpp		TempTreeView.h		v3ext.cpp
MW_menu.cpp		X509SuperTreeView.cpp	v3ext.h
MainWindow.cpp		X509SuperTreeView.h	validity.cpp
MainWindow.h		XcaApplication.cpp	validity.h
)

list(TRANSFORM xca_sources PREPEND ${PROJECT_SOURCE_DIR}/widgets/)
target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${xca_sources})
