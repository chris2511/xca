/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "MainWindow.h"
#include "PwDialog.h"
#include "Options.h"
#include "lib/load_obj.h"
#include "lib/pass_info.h"
#include "lib/pkcs11.h"
#include "lib/pki_evp.h"
#include "lib/pki_scard.h"
#include "lib/func.h"
#include "lib/db_x509super.h"
#include "ui_Options.h"
#include "hashBox.h"
#include "OidResolver.h"
#include "OpenDb.h"
#include <QApplication>
#include <QClipboard>
#include <QMenuBar>
#include <QMessageBox>

class myLang
{
public:
	QString english, native;
	QLocale locale;
	myLang(QString e, QString n, QLocale l) {
		english = e; native = n, locale = l;
	}
};

void MainWindow::init_menu()
{
	static QMenu *file = NULL, *help = NULL, *import = NULL,
			*token = NULL, *languageMenu = NULL, *extra = NULL;
	static QActionGroup * langGroup = NULL;
	QAction *a;

	QList<myLang> languages;
	if (file) delete file;
	if (help) delete help;
	if (import) delete import;
	if (token) delete token;
	if (extra) delete extra;
	if (languageMenu) delete languageMenu;
	if (historyMenu) delete historyMenu;
	if (langGroup) delete langGroup;

	wdMenuList.clear();
	scardList.clear();
	acList.clear();

	langGroup = new QActionGroup(this);

	historyMenu = new tipMenu(tr("Recent DataBases") + " ...", this);
	connect(historyMenu, SIGNAL(triggered(QAction*)),
                this, SLOT(open_database(QAction*)));

	languages <<
		myLang("System",   tr("System"),   QLocale::system()) <<
		myLang("Croatian", tr("Croatian"), QLocale("hr")) <<
		myLang("English",  tr("English"),  QLocale("en")) <<
		myLang("French",   tr("French"),   QLocale("fr")) <<
		myLang("German",   tr("German"),   QLocale("de")) <<
		myLang("Russian",  tr("Russian"),  QLocale("ru")) <<
		myLang("Slovak",   tr("Slovak"),   QLocale("sk")) <<
		myLang("Spanish",  tr("Spanish"),  QLocale("es")) <<
		myLang("Polish",   tr("Polish"),   QLocale("pl")) <<
		myLang("Portuguese in Brazil",   tr("Portuguese in Brazil"),   QLocale("pt_BR")) <<
		myLang("Turkish",  tr("Turkish"),  QLocale("tr"));

	languageMenu = new tipMenu(tr("Language"), this);
	connect(languageMenu, SIGNAL(triggered(QAction*)),
		qApp, SLOT(switchLanguage(QAction*)));

	foreach(myLang l, languages) {
		QAction *a = new QAction(l.english, langGroup);
		a->setToolTip(l.native);
		a->setData(QVariant(l.locale));
		a->setDisabled(!XCA_application::languageAvailable(l.locale));
		a->setCheckable(true);
		langGroup->addAction(a);
		languageMenu->addAction(a);
		if (l.locale == XCA_application::language())
			a->setChecked(true);
	}
	file = menuBar()->addMenu(tr("&File"));
	file->addAction(tr("&New DataBase"), this, SLOT(new_database()),
			QKeySequence::New)
			->setEnabled(OpenDb::hasSqLite());
	file->addAction(tr("&Open DataBase"), this, SLOT(load_database()),
			QKeySequence::Open)
			->setEnabled(OpenDb::hasSqLite());
	file->addAction(tr("Open Remote DataBase"),
			this, SLOT(openRemoteSqlDB()))
			->setEnabled(OpenDb::hasRemoteDrivers());
	file->addMenu(historyMenu);
	if (!portable_app()) {
		file->addAction(tr("Set as default DataBase"), this,
				SLOT(default_database()));
	}
	acList += file->addAction(tr("&Close DataBase"), this,
		SLOT(close_database()), QKeySequence(QKeySequence::Close));

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
	import->addAction(tr("Paste PEM file"), this, SLOT(pastePem()));

	token = menuBar()->addMenu(tr("&Token"));
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
	acList += extra->addAction(tr("&Export Certificate Index hierarchy"), this,
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
	help->addAction(tr("&Content"), this, SLOT(help()),
			QKeySequence::HelpContents);
	a = new QAction(tr("About"), this);
	connect(a, SIGNAL(triggered()), this, SLOT(about()));
	a->setMenuRole(QAction::AboutRole);
	help->addAction(a);
	wdMenuList += import;
	scardList += token;

	setItemEnabled(!currentDB.isEmpty());
}

int MainWindow::changeDB(QString fname)
{
	if (fname.isEmpty())
		return 1;
	close_database();
	if (!OpenDb::isRemoteDB(fname))
		homedir = fname.mid(0, fname.lastIndexOf(QDir::separator()));
	return init_database(fname);
}

void MainWindow::update_history_menu()
{
	historyMenu->clear();
	for (int i = 0, j = 0; i < history.size(); i++) {
		QAction *a;
		QString txt = history[i];
		if (!QFile::exists(txt) && !OpenDb::isRemoteDB(txt))
			continue;
		txt = txt.remove(0, txt.lastIndexOf(QDir::separator()) +1);
		if (txt.size() > 20)
			txt = QString("...") + txt.mid(txt.size() - 20);
		a = historyMenu->addAction(QString("%1 %2").arg(j++).arg(txt));
		a->setData(QVariant(history[i]));
		a->setToolTip(history[i]);
	}
}

void MainWindow::open_database(QAction* a)
{
	changeDB(a->data().toString());
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
	changeDB(getFullFilename(fname, selectedFilter));
}

void MainWindow::load_database()
{
	load_db l;
	QString fname = QFileDialog::getOpenFileName(this, l.caption, homedir,
			l.filter);
	changeDB(fname);
}

void MainWindow::setOptions()
{
	if (!QSqlDatabase::database().isOpen())
		return;

	Options *opt = new Options(this);

	if (!opt->exec()) {
		delete opt;
		enableTokenMenu(pkcs11::loaded());
		return;
	}

	certView->showHideSections();
	reqView->showHideSections();

	enableTokenMenu(pkcs11::loaded());
	delete opt;
}
