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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "lib/base.h"
#include "MainWindow_UI.h"
#include "KeyDetail.h"
#include "ReqDetail.h"
#include "CertDetail.h"
#include "PassRead.h"
#include "PassWrite.h"
#include "NewKey.h"
#include "NewX509.h"
#include "NewX509_UI.h"
#include "CertExtend.h"
#include "TrustState.h"
#include "ExportCert.h"
#include "ExportKey.h"
#include "ExportTinyCA.h"
#include <iostream>
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
#include <qinputdialog.h>
#include <qcheckbox.h>
#include <qprogressdialog.h>
#include <qpushbutton.h>
#include <qasciidict.h>
#include <qpixmap.h>
#include <qobject.h>
#include <qmultilineedit.h>
#include "lib/pki_key.h"
#include "lib/pki_x509req.h"
#include "lib/pki_x509.h"
#include "lib/pki_pkcs12.h"
#include "lib/pki_pkcs7.h"
#include "lib/pki_temp.h"
#include "lib/db_key.h"
#include "lib/db_x509req.h"
#include "lib/db_x509.h"
#include "lib/db_temp.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#define DBFILE "xca.db"


class MainWindow: public MainWindow_UI
{
	Q_OBJECT
   protected:
	void addStr(string &str, const char *add);
	void init_images();
	void read_cmdline();
	void init_database();
	DbTxn *global_tid;
			    
   friend class pki_key;
	db_x509 *certs;
	db_x509req *reqs;
	db_key *keys;
	db_temp *temps;
	DbEnv *dbenv;
	db_base *settings;
	static QPixmap *keyImg, *csrImg, *certImg, *tempImg, *nsImg, *revImg, *appIco;

   public:
	int exitApp;
	QString baseDir, dbfile;
	static const int sizeList[];
	MainWindow(QWidget *parent, const char *name);
	~MainWindow(); 
	void loadSettings();
	void saveSettings();
	void initPass();
	bool showDetailsKey(pki_key *key, bool import = false);
	void showDetailsReq(pki_x509req *req, bool import = false);
	bool showDetailsCert(pki_x509 *cert, bool import = false);
	bool showDetailsTemp(pki_temp *temp);
	static int passRead(char *buf, int size, int rwflag, void *userdata);
	static int passWrite(char *buf, int size, int rwflag, void *userdata);
	static void incProgress(int a, int b, void *progress);
	static void dberr(const char *errpfx, char *msg);
	pki_key *getSelectedKey();
	pki_key *insertKey(pki_key *lkey);
	pki_x509req *insertReq(pki_x509req *req);
	pki_x509 *insertCert(pki_x509 *cert);
	void insertP12(pki_pkcs12 *pk12);
	void insertTemp(pki_temp *temp);
	string md5passwd();
	bool opensslError(pki_base *pki);
	QPixmap *loadImg(const char *name);
	void renamePKI(db_base *db);
	bool alterTemp(pki_temp *temp);
	void Error(errorEx &err);
	void writePKCS12(QString s, bool chain);
	void setPath(QFileDialog *dlg);
	QString getPath();
	void newPath(QFileDialog *dlg);
	void newPath(QString str);
	bool mkDir(QString dir);
   public slots:
	void loadKey();
	void loadReq();
	void loadCert();
	void loadPKCS12();
	void loadPKCS7();
	void newKey();
	void newReq(pki_temp *templ);
	void newCert(pki_temp *templ);
	void newCert(pki_x509req *req);
	void newCert(NewX509 *dlg);
	void newReq(){newReq(NULL);}
	void newCert();
	void newTemp(int type = tEMPTY);
	void newEmpTemp(){ newTemp(tEMPTY); }
	void newCATemp(){ newTemp(tCA); }
	void newCliTemp(){ newTemp(tCLIENT); }
	void newSerTemp(){ newTemp(tSERVER); }
	void certFromTemp();
	void reqFromTemp();
	void showDetailsKey(QListViewItem *item);
	void showDetailsKey();
	void showDetailsReq(QListViewItem *item);
	void showDetailsReq();
	void showDetailsCert();
	void showDetailsCert(QListViewItem *item);
	void deleteKey();
	void deleteReq();
	void deleteCert();
	void deleteTemp();
	void writeKey();
	void writeReq();
	void writeCert();
	void showPopupCert(QListViewItem *item,const QPoint &pt, int x);
	void showPopupKey(QListViewItem *item,const QPoint &pt, int x);
	void showPopupReq(QListViewItem *item,const QPoint &pt, int x);
	void showPopupTemp(QListViewItem *item,const QPoint &pt, int x);
	void startRenameCert();
	void startRenameKey();
	void startRenameReq();
	void startRenameTemp();
	void setTrust();
	void revoke();
	void unRevoke();
	void renameKey(QListViewItem *item, int col, const QString &text);
	void renameReq(QListViewItem *item, int col, const QString &text);
	void renameCert(QListViewItem *item, int col, const QString &text);
	void renameTemp(QListViewItem *item, int col, const QString &text);
	void alterTemp();
	void setSerial();
	void setCrlDays();
	void setTemplate();
	void genCrl();
	void signReq();
	void crashApp();
	void toRequest();
	void extendCert();
	void signP7();
	void encryptP7();
	void changeView();
	void toTinyCA();
   signals:
	void keyDone(QString name);
};
#endif
