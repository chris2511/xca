#include "lib/pki_key.h"
#include "lib/pki_x509req.h"
#include "lib/pki_x509.h"
#include "lib/db_key.h"
#include "lib/db_x509req.h"
#include "lib/db_x509.h"
#include "MainWindow_UI.h"
#include "KeyDetail_UI.h"
#include "ReqDetail_UI.h"
#include "PassRead_UI.h"
#include "PassWrite_UI.h"
#include "NewKey_UI.h"
#include "NewX509Req_UI.h"
#include "NewX509_UI.h"
#include "ExportKey.h"
#include <iostream.h>
#include <qapplication.h>
#include <qdir.h>
#include <qlineedit.h>
#include <qcombobox.h>
#include <qlistbox.h>
#include <qobjectlist.h>
#include <qobjcoll.h>
#include <qlabel.h>
#include <qfiledialog.h>
#include <qmessagebox.h>
#include <qcheckbox.h>
#include <qprogressdialog.h>

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#define BASE_DIR "/xca"
#define DBFILE "xca.db"


class MainWindow: public MainWindow_UI
{
	Q_OBJECT
	db_x509 *certs;
	db_x509req *reqs;
	db_key *keys;
	DbEnv *dbenv;
   public:
	QString baseDir;
	static const int sizeList[];
	MainWindow(QWidget *parent, const char *name);
	~MainWindow(); 
	void showDetailsKey(pki_key *key);
	static int passRead(char *buf, int size, int rwflag, void *userdata);
	static int passWrite(char *buf, int size, int rwflag, void *userdata);
	static void incProgress(int a, int b, void *progress);
	pki_key *getSelectedKey();
   public slots:
	void loadKey();
	void loadReq();
	void newKey();
	void newReq();
	void newCert();
	void showDetailsKey();
	void showDetailsReq();
	void deleteKey();
	void deleteReq();
	void writeKey();
	void writeReq();
};
#endif
