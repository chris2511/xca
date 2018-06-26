/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __MAINWINDOW_H
#define __MAINWINDOW_H

#include "NewX509.h"
#include "XcaWarning.h"
#include "OidResolver.h"
#include "ui_MainWindow.h"
#include "lib/db_key.h"
#include "lib/db_x509req.h"
#include "lib/db_x509.h"
#include "lib/db_temp.h"
#include "lib/db_crl.h"
#include "lib/exception.h"
#include "lib/oid.h"
#include "lib/Passwd.h"
#include "lib/settings.h"
#include "lib/main.h"
#include <QPixmap>
#include <QFileDialog>
#include <QMenuBar>
#include <QList>
#include <QtSql>
#include <QMenu>
#include <QToolTip>
#include <QLocale>

class db_x509;
class pki_multi;

class tipMenu : public QMenu
{
	Q_OBJECT

    public:
	tipMenu(QString n, QWidget *w) : QMenu(n, w) {}
	bool event (QEvent * e)
	{
		const QHelpEvent *helpEvent = static_cast <QHelpEvent *>(e);
		if (helpEvent->type() == QEvent::ToolTip && activeAction() &&
		    activeAction()->toolTip() != activeAction()->text()) {
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
		static OidResolver *resolver;
		QString string_opt;
		QList<QWidget*> wdList;
		QList<QWidget*> wdMenuList;
		QList<QWidget*> scardList;
		QList<QAction*> acList;
		QStringList history;
		tipMenu *historyMenu;
		void update_history_menu();
		void set_geometry(QString geo);
		QLineEdit *searchEdit;
		QStringList urlsToOpen;
		int checkOldGetNewPass(Passwd &pass);
		int exportIndex(QString fname, bool hierarchy);
		void checkDB();
		QSqlError initSqlDB();
		QString openSqlDB(QString dbName);
		QTimer *eachSecond;

	protected:
		void init_images();
		void init_menu();
		int force_load;
		NIDlist *read_nidlist(QString name);
		QLabel *statusLabel;
		QString homedir;
		int changeDB(QString fname);
		void keyPressEvent(QKeyEvent *e);

	public:
		static db_x509 *certs;
		static db_x509req *reqs;
		static db_key *keys;
		static db_temp *temps;
		static db_crl *crls;
		static QPixmap *keyImg, *csrImg, *certImg, *tempImg,
				*nsImg, *revImg, *appIco, *scardImg,
				*doneIco, *warnIco;
		static NIDlist *eku_nid, *dn_nid;
		int exitApp;
		QLabel *dbindex;

		MainWindow(QWidget *parent);
		virtual ~MainWindow();
		void loadSettings();
		void saveSettings();
		int initPass(QString dbName);
		int initPass(QString dbName, QString passhash);
		void read_cmdline(int argc, char *argv[]);
		void load_engine();
		static OidResolver *getResolver()
		{
			return resolver;
		}
		static void Error(errorEx &err);
		static void dbSqlError(QSqlError err = QSqlError());

		void cmd_version();
		void cmd_help(const char* msg);

		bool mkDir(QString dir);
		void setItemEnabled(bool enable);
		void enableTokenMenu(bool enable);
		pki_multi *probeAnything(QString file, int *ret = NULL);
		void importAnything(QString file);
		void dropEvent(QDropEvent *event);
		void dragEnterEvent(QDragEnterEvent *event);
		int open_default_db();
		void load_history();
		void update_history(QString file);
		void initResolver();
		bool checkForOldDbFormat();
		bool checkForOldDbFormat(QString dbfile);
		int verifyOldDbPass(QString dbname);
		void importOldDatabase(QString dbname);

	public slots:
		int init_database(QString dbName);
		void new_database();
		void load_database();
		void close_database();
		void dump_database();
		void default_database();
		void connNewX509(NewX509 *nx);
		void about();
		void help();
		void undelete();
		void loadPem();
		bool pastePem(QString text, bool silent=false);
		void pastePem();
		void changeDbPass();
		void openURLs(QStringList &files);
		void openURLs();
		void changeEvent(QEvent *event);
		void exportIndex();
		void exportIndexHierarchy();
		void openRemoteSqlDB();

	protected slots:
		void closeEvent(QCloseEvent * event);

	private slots:
		void setOptions();
		void manageToken();
		void initToken();
		void changePin(bool so=false);
		void changeSoPin();
		void initPin();
		void generateDHparam();
		void open_database(QAction* a);
};
#endif
