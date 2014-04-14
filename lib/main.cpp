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
#include "widgets/MainWindow.h"
#include "lib/func.h"
#include "lib/main.h"
#ifdef WIN32
#include <windows.h>
#endif

void XCA_application::setMainwin(MainWindow *m)
{
	mainw = m;
	connect(this, SIGNAL(openFiles(QStringList &)),
		m, SLOT(openURLs(QStringList &)));
}

XCA_application::XCA_application(int &argc, char *argv[])
	:QApplication(argc, argv)
{
	QLocale sys = QLocale::system();
	QStringList dirs;

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
		if (qtTr.load(sys, "qt", dir)) {
			break;
		}
	}
	xcaTr.load(sys, "xca", getPrefix());

	installTranslator(&qtTr);
	installTranslator(&xcaTr);

#ifdef Q_WS_MAC
	QStringList libp = libraryPaths();
	libp.prepend(applicationDirPath() + "/../Plugins");
	setLibraryPaths(libp);
#endif
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

	XCA_application a( argc, argv );
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
