/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "MainWindow.h"
#include "XcaApplication.h"
#include "PwDialog.h"
#include "Options.h"
#include "lib/load_obj.h"
#include "lib/pass_info.h"
#include "lib/pkcs11.h"
#include "lib/pki_evp.h"
#include "lib/pki_scard.h"
#include "lib/func.h"
#include "lib/db_x509super.h"
#include "lib/database_model.h"
#include "ui_Options.h"
#include "hashBox.h"
#include "OidResolver.h"
#include "OpenDb.h"
#include "Help.h"
#include <QApplication>
#include <QClipboard>
#include <QMenuBar>
#include <QMessageBox>
#include <QFileDialog>

static QAction *languageMenuEntry(const QStringList &sl)
{
	QString lang, tooltip;
	QLocale locale;

	if (sl[0].isEmpty()) {
		locale = QLocale::system();
		lang = MainWindow::tr("System");
	} else {
		locale = QLocale(sl[0]);
		lang = QString("%1 (%2)").arg(sl[1])
			.arg(QLocale::languageToString(locale.language()));
	}
	tooltip = locale.nativeLanguageName();

	if (sl.length() > 2)
		tooltip += " - " + sl[2];

	QAction *a = new QAction(lang, NULL);
	a->setToolTip(tooltip);
	a->setData(QVariant(locale));
	a->setDisabled(!XcaApplication::languageAvailable(locale));

	a->setCheckable(true);
	if (locale == XcaApplication::language())
		a->setChecked(true);
	return a;
}

void MainWindow::init_menu()
{
	static QMenu *file = NULL, *help = NULL, *import = NULL,
			*token = NULL, *languageMenu = NULL, *extra = NULL;
	static QActionGroup * langGroup = NULL;
	QAction *a;

	delete file;
	delete help;
	delete import;
	delete token;
	delete extra;
	delete languageMenu;
	delete historyMenu;
	delete langGroup;

	wdMenuList.clear();
	scardList.clear();
	acList.clear();

	langGroup = new QActionGroup(this);

	historyMenu = new tipMenu(tr("Recent DataBases") + " ...", this);
	update_history_menu();

	connect(historyMenu, SIGNAL(triggered(QAction*)),
                this, SLOT(open_database(QAction*)));

	languageMenu = new tipMenu(tr("Language"), this);
	connect(languageMenu, SIGNAL(triggered(QAction*)),
		qApp, SLOT(switchLanguage(QAction*)));

	foreach(const QStringList &sl, getTranslators()) {
		QAction *a = languageMenuEntry(sl);
		langGroup->addAction(a);
		languageMenu->addAction(a);
	}
	file = menuBar()->addMenu(tr("&File"));
	file->addAction(tr("New DataBase"), this, SLOT(new_database()),
			QKeySequence::New)
			->setEnabled(OpenDb::hasSqLite());
	file->addAction(tr("Open DataBase"), this, SLOT(load_database()),
			QKeySequence::Open)
			->setEnabled(OpenDb::hasSqLite());
	file->addAction(tr("Open Remote DataBase"),
			this, SLOT(openRemoteSqlDB()))
			->setEnabled(OpenDb::hasRemoteDrivers());
	file->addMenu(historyMenu);
	file->addAction(tr("Set as default DataBase"), this,
				SLOT(default_database()));
	acList += file->addAction(tr("Close DataBase"), this,
		SLOT(close_database()), QKeySequence::Close);

	a = new QAction(tr("Options"), this);
	connect(a, SIGNAL(triggered()), this, SLOT(setOptions()));
	a->setMenuRole(QAction::PreferencesRole);
	file->addAction(a);
	acList += a;

	file->addMenu(languageMenu);
	file->addSeparator();
	a = new QAction(tr("Exit"), this);
	connect(a, SIGNAL(triggered()),
		qApp, SLOT(quit()), Qt::QueuedConnection);
	a->setMenuRole(QAction::QuitRole);
	a->setShortcut(QKeySequence::Quit);
	file->addAction(a);

	import = menuBar()->addMenu(tr("I&mport"));
	import->addAction(tr("Keys"), keyView, SLOT(load()) );
	import->addAction(tr("Requests"), reqView, SLOT(load()) );
	import->addAction(tr("Certificates"), certView, SLOT(load()) );
	import->addAction(tr("PKCS#12"), certView, SLOT(loadPKCS12()) );
	import->addAction(tr("PKCS#7"), certView, SLOT(loadPKCS7()) );
	import->addAction(tr("Template"), tempView, SLOT(load()) );
	import->addAction(tr("Revocation list"), crlView, SLOT(load()));
	import->addAction(tr("PEM file"), this, SLOT(loadPem()) );
	import->addAction(tr("Paste PEM file"), this, SLOT(pastePem()),
			QKeySequence::Paste);

	token = menuBar()->addMenu(tr("Token"));
	token->addAction(tr("&Manage Security token"), this,
				SLOT(manageToken()));
	token->addAction(tr("&Init Security token"),  this,
				SLOT(initToken()));
	token->addAction(tr("&Change PIN"), this,
				SLOT(changePin()) );
	token->addAction(tr("Change &SO PIN"), this,
				SLOT(changeSoPin()) );
	token->addAction(tr("Init PIN"), this,
				SLOT(initPin()) );

	extra = menuBar()->addMenu(tr("Extra"));
	acList += extra->addAction(tr("&Dump DataBase"), this,
				SLOT(dump_database()));
	acList += extra->addAction(tr("&Export Certificate Index"), this,
				SLOT(exportIndex()));
	acList += extra->addAction(tr("Export Certificate &Index hierarchy"), this,
				SLOT(exportIndexHierarchy()));
	acList += extra->addAction(tr("C&hange DataBase password"), this,
				SLOT(changeDbPass()));
#if 0
	acList += extra->addAction(tr("&Undelete items"), this,
				SLOT(undelete()));
#endif
	extra->addAction(tr("Generate DH parameter"), this,
				 SLOT(generateDHparam()));
	extra->addAction(tr("OID Resolver"), resolver, SLOT(show()));

	help = menuBar()->addMenu(tr("&Help") );
	help->addAction(tr("Content"), helpdlg, SLOT(content()),
			QKeySequence::HelpContents);
	a = new QAction(tr("About"), this);
	connect(a, SIGNAL(triggered()), this, SLOT(about()));
	a->setMenuRole(QAction::AboutRole);
	a->setShortcut(QKeySequence::WhatsThis);
	help->addAction(a);
	wdMenuList += import;
	scardList += token;

	setItemEnabled(Database.isOpen());
}

void MainWindow::update_history_menu()
{
	QStringList hist = history.get();
	if (!historyMenu)
		return;
	historyMenu->clear();
	for (int i = 0, j = 0; i < hist.size(); i++) {
		QAction *a;
		QString txt = hist[i];
		if (!QFile::exists(txt) && !database_model::isRemoteDB(txt))
			continue;
		txt = QFileInfo(txt).fileName();
		if (txt.size() > 20)
			txt = QString("...") + txt.mid(txt.size() - 20);
		a = historyMenu->addAction(QString("%1 %2").arg(j++).arg(txt));
		a->setData(QVariant(hist[i]));
		a->setToolTip(hist[i]);
	}
}

void MainWindow::open_database(QAction* a)
{
	init_database(a->data().toString());
}

void MainWindow::new_database()
{
	load_db l;
	QString selectedFilter;
	QString fname = QFileDialog::getSaveFileName(this, l.caption, homedir,
			l.filter, &selectedFilter, QFileDialog::DontConfirmOverwrite);
	// make sure that, if the 3 letter extension was left selected
	// in Qt's OS X file open dialog,
	// the filename actually ends with that extension.
	// Otherwise usability breaks in jarring ways.
	init_database(getFullFilename(fname, selectedFilter));
}

void MainWindow::load_database()
{
	load_db l;
	QString fname = QFileDialog::getOpenFileName(this, l.caption, homedir,
			l.filter);
	init_database(fname);
}

void MainWindow::setOptions()
{
	if (!QSqlDatabase::database().isOpen())
		return;

	Options *opt = new Options(this);
	if (opt->exec()) {
		reqView->showHideSections();
		certView->showHideSections();
	}
	delete opt;

	pkcs11::libraries.load(Settings["pkcs11path"]);
	enableTokenMenu(pkcs11::libraries.loaded());
}
