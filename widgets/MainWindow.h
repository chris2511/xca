/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __MAINWINDOW_H
#define __MAINWINDOW_H

#include "NewX509.h"
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
#include "lib/main.h"
#include <QPixmap>
#include <QFileDialog>
#include <QMenuBar>
#include <QList>
#include <QMessageBox>
#include <QMenu>
#include <QToolTip>
#include <QLocale>

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
		QString workingdir;
		QString string_opt;
		QString pkcs11path;
		QList<QWidget*> wdList;
		QList<QWidget*> wdMenuList;
		QList<QWidget*> scardList;
		QList<QAction*> acList;
		QStringList history;
		tipMenu *historyMenu;
		void update_history_menu();
		void set_geometry(char *p, db_header_t *head);
		QLineEdit *searchEdit;
		QStringList urlsToOpen;
		int checkOldGetNewPass(Passwd &pass);
		QString updateDbPassword(QString newdb, Passwd pass);

	protected:
		void init_images();
		void init_menu();
		int force_load;
		NIDlist *read_nidlist(QString name);
		QLabel *statusLabel;
		QString homedir;
		int changeDB(QString fname);
		void setOptFlags(QString flags);
		void setOptFlags_old(QString flags);
		QString getOptFlags();
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
		void read_cmdline(int argc, char *argv[]);
		void load_engine();
		static OidResolver *getResolver()
		{
			return resolver;
		}
		static void Error(errorEx &err);
		void cmd_version();
		void cmd_help(const char* msg);

		QString getPath();
		void setPath(QString path);
		bool mkDir(QString dir);
		void setItemEnabled(bool enable);
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
		void help();
		void import_dbdump();
		void undelete();
		void loadPem();
		bool pastePem(QString text);
		void pastePem();
		void changeDbPass();
		void openURLs(QStringList &files);
		void openURLs();
		void changeEvent(QEvent *event);

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
