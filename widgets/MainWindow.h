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
#include "lib/database_model.h"
#include "lib/dbhistory.h"

#include <QPixmap>
#include <QFileDialog>
#include <QMenuBar>
#include <QList>
#include <QtSql>
#include <QMenu>
#include <QToolTip>
#include <QLocale>
#include <QProgressBar>

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

class DHgen;
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
		tipMenu *historyMenu;
		void set_geometry(QString geo);
		QLineEdit *searchEdit;
		QStringList urlsToOpen;
		int checkOldGetNewPass(Passwd &pass);
		void checkDB();
		QProgressBar *dhgenBar;
		DHgen *dhgen;
		const QList<QStringList> getTranslators() const;
		QList<XcaTreeView *> views;
		database_model *models;
		dbhistory history;
		void exportIndex(const QString &fname, bool hierarchy) const;

	protected:
		void init_images();
		void init_menu();
		int force_load;
		NIDlist *read_nidlist(QString name);
		QLabel *statusLabel;
		QString homedir;
		int changeDB(QString fname);
		void keyPressEvent(QKeyEvent *e);
		void update_history_menu();

	public:
		int exitApp;
		QLabel *dbindex;
		database_model *getModels()
		{
			return models;
		}
		template <class T>  T *model() const
		{
			return models ? models->model<T>() : NULL;
		}
		MainWindow(database_model *m);
		virtual ~MainWindow();
		void loadSettings();
		void saveSettings();
		void load_engine();
		static OidResolver *getResolver()
		{
			return resolver;
		}
		bool mkDir(QString dir);
		void setItemEnabled(bool enable);
		void enableTokenMenu(bool enable);
		void importAnything(QString file);
		void importAnything(const QStringList &files);
		void importMulti(pki_multi *multi, int force);
		void dropEvent(QDropEvent *event);
		void dragEnterEvent(QDragEnterEvent *event);
		void initResolver();

	public slots:
		enum open_result init_database(const QString &dbName,
				const Passwd &pass = Passwd());
		enum open_result init_database(database_model *m);
		void new_database();
		void load_database();
		void close_database();
		void dump_database();
		void default_database();
		void connNewX509(NewX509 *nx);
		void about();
		void help();
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
		void generateDHparamDone();

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
