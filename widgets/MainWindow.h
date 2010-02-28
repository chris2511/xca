/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef _MAINWINDOW_H
#define _MAINWINDOW_H

#include "NewX509.h"
#include "ui_MainWindow.h"
#include "lib/db_key.h"
#include "lib/db_x509req.h"
#include "lib/db_x509.h"
#include "lib/db_temp.h"
#include "lib/db_crl.h"
#include "lib/exception.h"
#include "lib/oid.h"
#include <qpixmap.h>
#include <qfiledialog.h>
#include <qmenubar.h>
#include <qlist.h>

#define DBFILE "xca.xdb"

class db_x509;

class MainWindow: public QMainWindow, public Ui::MainWindow
{
	Q_OBJECT

	private:
		QString workingdir;
		QString string_opt;
		QString pkcs11path;
		QList<QWidget*> wdList;
		QList<QAction*> acList;
		QList<QAction*> scardMenuActions;

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
		static QPixmap *keyImg, *csrImg, *certImg, *tempImg,
				*nsImg, *revImg, *appIco, *scardImg;
		static NIDlist *eku_nid, *dn_nid, *aia_nid;
		static QString mandatory_dn;
		int exitApp;
		QString dbfile;
		QLabel *dbindex;

		MainWindow(QWidget *parent);
		virtual ~MainWindow();
		void loadSettings();
		void saveSettings();
		int initPass();
		void read_cmdline();
		void load_engine();
		static int passRead(char *buf, int size, int rwflag, void *userdata);
		static int passWrite(char *buf, int size, int rwflag, void *userdata);
		//static void Qt::SocketError(errorEx &err);
		static void Error(errorEx &err);
		void cmd_version();
		void cmd_help(const char* msg);

		QString getPath();
		void setPath(QString path);
		bool mkDir(QString dir);
		void setItemEnabled(bool enable);
		QString updateDbPassword(QString newdb, char *pass);
		void enableTokenMenu(bool enable);

	public slots:
		void init_database();
		void new_database();
		void load_database();
		void close_database();
		void dump_database();
		void connNewX509(NewX509 *nx);
		void about();
		void donations();
		void help();
		void import_dbdump();
		void undelete();
		void loadPem();
		void pastePem();
		void changeDbPass();

	private slots:
		void setOptions();
		void importScard();
		void initToken();
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
