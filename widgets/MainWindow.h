/* vi: set sw=4 ts=4: */
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
 *	written by Eric Young (eay@cryptsoft.com)"
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

#ifndef _MAINWINDOW_H
#define _MAINWINDOW_H

#include "NewX509.h"
#include "ui/MainWindow.h"
#include "lib/db_key.h"
#include "lib/db_x509req.h"
#include "lib/db_x509.h"
#include "lib/db_temp.h"
#include "lib/db_crl.h"
#include "lib/exception.h"
#include "lib/oid.h"
#include <Qt/qpixmap.h>
#include <Qt/qfiledialog.h>
#include <Qt/qmenubar.h>
#include <Qt/qlist.h>

#define DBFILE "xca.xdb"


class db_x509;

class MainWindow: public QMainWindow, public Ui::MainWindow
{
	Q_OBJECT

	private:
		QString workingdir;
		QList<QWidget*> wdList;
		QList<QAction*> acList;

	protected:
		void init_images();
		void init_menu();
		int force_load;
		NIDlist *read_nidlist(QString name);
		QLabel *statusLabel;
		QString homedir;

	public:
		static db_x509 *certs;
		static db_x509req *reqs;
		static db_key *keys;
		static db_temp *temps;
		static db_crl *crls;
		static db_base *settings;
		static QPixmap *keyImg, *csrImg, *certImg, *tempImg, *nsImg, *revImg, *appIco;
		static NIDlist *eku_nid, *dn_nid, *aia_nid;
		int exitApp;
		QString dbfile;
		QLabel *dbindex;

		MainWindow(QWidget *parent);
		virtual ~MainWindow();
		void loadSettings();
		void saveSettings();
		int initPass();
		void read_cmdline();
		static int passRead(char *buf, int size, int rwflag, void *userdata);
		static int passWrite(char *buf, int size, int rwflag, void *userdata);
		//static void Qt::SocketError(errorEx &err);
		static void Error(errorEx &err);
		void cmd_help(const char* msg);

		QString getPath();
		void setPath(QString path);
		bool mkDir(QString dir);
		void setEnabled(bool enable);

	public slots:
		void init_database();
		void load_database();
		void close_database();
		void dump_database();
		void connNewX509(NewX509 *nx);
		void about();
		void help();
		void import_dbdump();

	private slots:
		void on_keyView_doubleClicked(const QModelIndex &m);
		void on_reqView_doubleClicked(const QModelIndex &m);
		void on_certView_doubleClicked(const QModelIndex &m);
		void on_tempView_doubleClicked(const QModelIndex &m);
		void on_crlView_doubleClicked(const QModelIndex &m);

		void on_BNnewKey_clicked();
		void on_BNdeleteKey_clicked();
		void on_BNdetailsKey_clicked();
		void on_BNimportKey_clicked();
		void on_BNexportKey_clicked();
		void on_BNimportPFX_clicked();

		void on_BNnewReq_clicked();
		void on_BNdeleteReq_clicked();
		void on_BNdetailsReq_clicked();
		void on_BNimportReq_clicked();
		void on_BNexportReq_clicked();

		void on_BNnewCert_clicked();
		void on_BNdeleteCert_clicked();
		void on_BNdetailsCert_clicked();
		void on_BNimportCert_clicked();
		void on_BNexportCert_clicked();
		void on_BNimportPKCS12_clicked();
		void on_BNimportPKCS7_clicked();
		void on_BNviewState_clicked();

		void on_BNnewTemp_clicked();
		void on_BNdeleteTemp_clicked();
		void on_BNchangeTemp_clicked();
		void on_BNimportTemp_clicked();
		void on_BNexportTemp_clicked();

		void on_BNdeleteCrl_clicked();
		void on_BNdetailsCrl_clicked();
		void on_BNimportCrl_clicked();
		void on_BNexportCrl_clicked();
};
#endif
