HEADERS = ExportKey.h MainWindow.h NewX509.h lib/db_base.h lib/db_key.h lib/db_temp.h lib/db_x509.h lib/db_x509req.h lib/pki_base.h lib/pki_key.h lib/pki_pkcs12.h lib/pki_temp.h lib/pki_x509.h lib/pki_x509req.h
SOURCES = ExportKey.cpp MainWindow.cpp MainWindowKeys.cpp MainWindowTemps.cpp MainWindowX509.cpp MainWindowX509Req.cpp NewX509.cpp main.cpp lib/db_base.cpp lib/db_key.cpp lib/db_temp.cpp lib/db_x509.cpp lib/db_x509req.cpp lib/pki_base.cpp lib/pki_key.cpp lib/pki_pkcs12.cpp lib/pki_temp.cpp lib/pki_x509.cpp lib/pki_x509req.cpp
FORMS   = CertDetail.ui ExportKey_UI.ui KeyDetail.ui MainWindow_UI.ui NewKey.ui NewX509_UI.ui PassRead.ui PassWrite.ui ReqDetail.ui TrustState.ui
TRANSLATIONS = xca_de.ts xca_es.ts
TARGET = xca
