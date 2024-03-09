/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __MAINWINDOW_H
#define __MAINWINDOW_H

#include "ui_MainWindow.h"

#include "lib/oid.h"
#include "lib/Passwd.h"
#include "lib/database_model.h"
#include "lib/dbhistory.h"
#include "lib/dhgen.h"
#include "lib/XcaProgress.h"

#include <QList>
#include <QMenu>
#include <QToolTip>
#include <QHelpEvent>

class db_x509;
class pki_multi;
class NewX509;
class OidResolver;
class QProgressBar;
class DHgen;
class Help;

extern MainWindow *mainwin;

class tipMenu : public QMenu
{
	Q_OBJECT

  public:
	tipMenu(QString n, QWidget *w) : QMenu(n, w) {}
	bool event (QEvent * e)
	{
		if (e->type() == QEvent::ToolTip && activeAction() &&
			activeAction()->toolTip() != activeAction()->text()) {
			const QHelpEvent *helpEvent = static_cast <QHelpEvent *>(e);
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
		QString string_opt{};
		QList<QWidget*> wdList{};
		QList<QWidget*> wdMenuList{};
		QList<QWidget*> scardList{};
		QList<QAction*> acList{};
		tipMenu *historyMenu{};
		QLineEdit *searchEdit{};
		QStringList urlsToOpen{};
		XcaProgress *dhgenProgress{};
		DHgen *dhgen{};
		QList<XcaTreeView *> views{};
		dbhistory history{};
		void set_geometry(QString geo);
		int checkOldGetNewPass(Passwd &pass);
		void checkDB();
		const QList<QStringList> getTranslators() const;
		void exportIndex(const QString &fname, bool hierarchy) const;
		QAction *languageMenuEntry(const QStringList &sl);

	protected:
		void init_images();
		void init_menu();
		int force_load;
		NIDlist *read_nidlist(QString name);
		QLabel *statusLabel;
		QString homedir;
		void keyPressEvent(QKeyEvent *e);
		void update_history_menu();
		void showDatabaseName();

	public:
		static bool legacy_loaded;
		int exitApp;
		QLabel *dbindex;
		Help *helpdlg;
		MainWindow();
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
		enum open_result setup_open_database();
		void new_database();
		void load_database();
		void close_database();
		void dump_database();
		void default_database();
		void about();
		void loadPem();
		bool pastePem(const QString &text, bool silent=false);
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
