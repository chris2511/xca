/*
 * Copyright (C) 2001 Christian Hohnstaedt.
 *
 *  All rights reserved.
 *
 *
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  - Neither the name of the author nor the names of its contributors may be 
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This program links to software with different licenses from:
 *
 *	http://www.openssl.org which includes cryptographic software
 * 	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.sleepycat.com
 *
 *	http://www.trolltech.com
 * 
 *
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$ 
 *
 */                           


#include "MainWindow_UI.h"
#include "KeyDetail_UI.h"
#include "ReqDetail_UI.h"
#include "CertDetail_UI.h"
#include "PassRead_UI.h"
#include "PassWrite_UI.h"
#include "NewKey_UI.h"
#include "NewX509Req.h"
#include "NewX509.h"
#include "NewX509_UI.h"
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
#include <qradiobutton.h>
#include <qlistview.h>
#include <qlistbox.h>
#include <qobjectlist.h>
#include <qobjcoll.h>
#include <qlabel.h>
#include <qfiledialog.h>
#include <qmessagebox.h>
#include <qcheckbox.h>
#include <qprogressdialog.h>
#include <qpushbutton.h>
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
   protected:
	void addStr(string &str, char *add);
   friend class pki_key;
	db_x509 *certs;
	db_x509req *reqs;
	db_key *keys;
	DbEnv *dbenv;
	db_base *settings;
	static QPixmap *keyImg, *csrImg, *certImg;
   public:
	QString baseDir, dbfile;
	static const int sizeList[];
	MainWindow(QWidget *parent, const char *name);
	~MainWindow(); 
	void loadSettings();
	void saveSettings();
	void initPass();
	bool showDetailsKey(pki_key *key, bool import = false);
	void showDetailsReq(pki_x509req *req);
	bool showDetailsCert(pki_x509 *cert, bool import = false);
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
	void loadPKCS12();
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
   signals:
	void keyDone(QString name);
};
#endif
