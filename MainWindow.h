#include "MainWindow_UI.h"
#include "KeyDetail_UI.h"
#include "ReqDetail_UI.h"
#include "CertDetail_UI.h"
#include "PassRead_UI.h"
#include "PassWrite_UI.h"
#include "NewKey_UI.h"
#include "NewX509Req_UI.h"
#include "NewX509.h"
#include "NewX509_1_UI.h"
#include "NewX509_2_UI.h"
#include "Rename_UI.h"
#include "TrustState_UI.h"
#include "ExportKey.h"
#include <iostream.h>
#include <qtextview.h>
#include <qapplication.h>
#include <qdir.h>
#include <qlineedit.h>
#include <qpopupmenu.h>
#include <qcombobox.h>
#include <qlistview.h>
#include <qlistbox.h>
#include <qobjectlist.h>
#include <qobjcoll.h>
#include <qlabel.h>
#include <qfiledialog.h>
#include <qmessagebox.h>
#include <qcheckbox.h>
#include <qprogressdialog.h>
#include <qasciidict.h>
#include <qpixmap.h>
#include <qobject.h>
#include "lib/pki_key.h"
#include "lib/pki_x509req.h"
#include "lib/pki_x509.h"
#include "lib/pki_pkcs12.h"
#include "lib/db_key.h"
#include "lib/db_x509req.h"
#include "lib/db_x509.h"

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#define BASE_DIR "/xca"
#define DBFILE "xca.db"

#ifndef CERR
#define CERR cerr
#endif

class MainWindow: public MainWindow_UI
{
	Q_OBJECT
   friend class pki_key;
	db_x509 *certs;
	db_x509req *reqs;
	db_key *keys;
	DbEnv *dbenv;
	db_base *settings;
	QPixmap *keyImg, *csrImg, *certImg;
   public:
	QString baseDir, dbfile;
	static const int sizeList[];
	MainWindow(QWidget *parent, const char *name);
	~MainWindow(); 
	void loadSettings();
	void saveSettings();
	void initPass();
	void showDetailsKey(pki_key *key);
	void showDetailsReq(pki_x509req *req);
	void showDetailsCert(pki_x509 *cert);
	static int passRead(char *buf, int size, int rwflag, void *userdata);
	static int passWrite(char *buf, int size, int rwflag, void *userdata);
	static void incProgress(int a, int b, void *progress);
	pki_key *getSelectedKey();
	void insertKey(pki_key *lkey);
	void insertCert(pki_x509 *cert);
	void insertReq(pki_x509req *req);
	string md5passwd();
	bool opensslError(pki_base *pki);
	QPixmap *loadImg(const char *name);
	void renamePKI(db_base *db);
   public slots:
	void loadKey();
	void loadReq();
	void loadCert();
	void newKey();
	void newReq();
	void newCert();
	void showDetailsKey(QListViewItem *item);
	void showDetailsKey();
	void showDetailsReq(QListViewItem *item);
	void showDetailsReq();
	void showDetailsCert();
	void showDetailsCert(QListViewItem *item);
	void deleteKey();
	void deleteReq();
	void deleteCert();
	void writeKey();
	void writeReq();
	void writeCert();
	void writePKCS12();
	void showPopupCert(QListViewItem *item,const QPoint &pt, int x);
	void showPopupKey(QListViewItem *item,const QPoint &pt, int x);
	void showPopupReq(QListViewItem *item,const QPoint &pt, int x);
	void startRenameCert();
	void startRenameKey();
	void startRenameReq();
	void setTrust();
	void revoke();
	void unRevoke();
	void renameKey(QListViewItem *item, int col, const QString &text);
	void renameReq(QListViewItem *item, int col, const QString &text);
	void renameCert(QListViewItem *item, int col, const QString &text);
};
#endif
