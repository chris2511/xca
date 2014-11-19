/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QtGui/QApplication>
#include <QtCore/QTranslator>
#include <QtCore/QTextCodec>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include "widgets/MainWindow.h"
#include "lib/func.h"
#include "lib/main.h"
#ifdef WIN32
#include <windows.h>
#endif

QLocale XCA_application::lang = QLocale::system();

void XCA_application::setMainwin(MainWindow *m)
{
	mainw = m;
	connect(this, SIGNAL(openFiles(QStringList &)),
		m, SLOT(openURLs(QStringList &)));
}

XCA_application::XCA_application(int &argc, char *argv[])
	:QApplication(argc, argv)
{
	qtTr = NULL;
	xcaTr = NULL;
	mainw = NULL;

	QFile file(getUserSettingsDir() +
			QDir::separator() + "defaultlang");

	if (file.open(QIODevice::ReadOnly)) {
		lang = QLocale(QString(file.read(128)));
	}
	setupLanguage(lang);
#ifdef Q_WS_MAC
	QStringList libp = libraryPaths();
	libp.prepend(applicationDirPath() + "/../Plugins");
	setLibraryPaths(libp);
#endif
}

void XCA_application::setupLanguage(QLocale l)
{
	QStringList dirs;

	lang = l;
	if (qtTr) {
		removeTranslator(qtTr);
		delete qtTr;
	}
	qtTr = new XcaTranslator();
	if (xcaTr) {
		removeTranslator(xcaTr);
		delete xcaTr;
	}
	xcaTr = new XcaTranslator();
	dirs
#ifdef XCA_DEFAULT_QT_TRANSLATE
		<< XCA_DEFAULT_QT_TRANSLATE
#endif
		<< getPrefix()
#ifndef WIN32
		<< "/usr/local/share/qt4/translations/"
		<< "/usr/share/qt4/translations/"
		<< "/usr/share/qt/translations/"
#endif
		;

	foreach(QString dir, dirs) {
		if (qtTr->load(lang, "qt", dir)) {
			break;
		}
	}
	xcaTr->load(lang, "xca", getPrefix());

	installTranslator(qtTr);
	installTranslator(xcaTr);
}

void XCA_application::switchLanguage(QAction* a)
{
	QLocale lang = a->data().toLocale();
	setupLanguage(lang);

	QString dir = getUserSettingsDir();
	QFile file(dir +QDir::separator() +"defaultlang");

	if (lang == QLocale::system()) {
		file.remove();
		return;
	}

	QDir d;
	d.mkpath(dir);
	if (file.open(QIODevice::WriteOnly)) {
		file.write(lang.name().toUtf8());
	}
}

bool XCA_application::event(QEvent *ev)
{
	if (ev->type() == QEvent::FileOpen) {
		QStringList l;
		l << static_cast<QFileOpenEvent *>(ev)->file();
		emit openFiles(l);
		return true;
	}
	return QApplication::event(ev);
}

int main( int argc, char *argv[] )
{
	int ret = 0, pkictr;
	MainWindow *mw;

	XCA_application a(argc, argv);
	mw = new MainWindow(NULL);
	try {
		a.setMainwin(mw);
		mw->read_cmdline();
		if (mw->exitApp == 0) {
			mw->load_history();
			if (mw->open_default_db() != 2) {
				mw->show();
				ret = a.exec();
			 }
		}
	} catch (errorEx &ex) {
		mw->Error(ex);
	}

	delete mw;
	pkictr =  pki_base::get_pki_counter();
	if (pkictr)
		fprintf(stderr, "PKI Counter (%d)\n", pkictr);

	return ret;
}
