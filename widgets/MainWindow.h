/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __MAINWINDOW_H
#define __MAINWINDOW_H

#include "NewX509.h"
#include "ui_MainWindow.h"
#include "lib/db_key.h"
#include "lib/db_x509req.h"
#include "lib/db_x509.h"
#include "lib/db_temp.h"
#include "lib/db_crl.h"
#include "lib/exception.h"
#include "lib/oid.h"
#include "lib/Passwd.h"
#include <QtGui/QPixmap>
#include <QtGui/QFileDialog>
#include <QtGui/QMenuBar>
#include <QtCore/QList>
#include <QtGui/QMessageBox>
#include <QtGui/QMenu>
#include <QtGui/QToolTip>

#define DBFILE "xca.xdb"

class db_x509;
class pki_multi;

class xcaWarning: public QMessageBox
{
	public:
		xcaWarning(QWidget *w, QString txt)
			: QMessageBox(QMessageBox::Warning,
				 XCA_TITLE, txt, QMessageBox::NoButton, w)
		{
			setTextFormat(Qt::PlainText);
		}
};

class tipMenu : public QMenu
{
	Q_OBJECT

    public:
	tipMenu(QString n, QWidget *w) : QMenu(n, w) {}
	bool event (QEvent * e)
	{
		const QHelpEvent *helpEvent = static_cast <QHelpEvent *>(e);
		if (helpEvent->type() == QEvent::ToolTip && activeAction()) {
			QToolTip::showText(helpEvent->globalPos(),
				activeAction()->toolTip());
		} else {
			QToolTip::hideText();
		}
		return QMenu::event(e);
	}
};

class MainWindow: public QMainWindow, public Ui::MainWindow
{
	Q_OBJECT

	private:
		QString workingdir;
		QString string_opt;
		QString pkcs11path;
		QList<QWidget*> wdList;
		QList<QWidget*> scardList;
		QList<QAction*> acList;
		QStringList history;
		tipMenu *historyMenu;
		void update_history_menu();

	protected:
		void init_images();
		void init_menu();
		int force_load;
		NIDlist *read_nidlist(QString name);
		QLabel *statusLabel;
		QString homedir;
		int changeDB(QString fname);
		void setOptFlags(QString flags);
		QString getOptFlags();

	public:
		static db_x509 *certs;
		static db_x509req *reqs;
		static db_key *keys;
		static db_temp *temps;
		static db_crl *crls;
		static QPixmap *keyImg, *csrImg, *certImg, *tempImg,
				*nsImg, *revImg, *appIco, *scardImg,
				*doneIco, *warnIco;
		static NIDlist *eku_nid, *dn_nid, *aia_nid;
		static QString mandatory_dn;
		static QString explicit_dn;
		static QString explicit_dn_default;
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
		static void Error(errorEx &err);
		void cmd_version();
		void cmd_help(const char* msg);

		QString getPath();
		void setPath(QString path);
		bool mkDir(QString dir);
		void setItemEnabled(bool enable);
		QString updateDbPassword(QString newdb, Passwd pass);
		void enableTokenMenu(bool enable);
		pki_multi *probeAnything(QString file, int *ret = NULL);
		void importAnything(QString file);
		void dropEvent(QDropEvent *event);
		void dragEnterEvent(QDragEnterEvent *event);
		int open_default_db();
		void setDefaultKey(QString def);
		void load_history();
		void update_history(QString file);

	public slots:
		int init_database();
		void new_database();
		void load_database();
		void close_database();
		void dump_database();
		void default_database();
		void connNewX509(NewX509 *nx);
		void about();
		void donations();
		void help();
		void import_dbdump();
		void undelete();
		void loadPem();
		bool pastePem(QString text);
		void pastePem();
		void changeDbPass();
		void openURLs(QStringList &files);

	signals:
		void newURLs(QStringList &);

	private slots:
		void setOptions();
		void manageToken();
		void initToken();
		void changePin(bool so=false);
		void changeSoPin();
		void initPin();
		void generateDHparam();
		void open_database(QAction* a);

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
