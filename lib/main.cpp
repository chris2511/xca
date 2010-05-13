/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <qapplication.h>
#include <qtranslator.h>
#include <qtextcodec.h>
#include <qdir.h>
#include <qtranslator.h>
#include "widgets/MainWindow.h"
#include "lib/func.h"
#ifdef WIN32
#include <windows.h>
#endif

int main( int argc, char *argv[] )
{
	int ret = 0, pkictr;
	QString locale;
	QTranslator qtTr;
	QTranslator xcaTr;
	MainWindow *mw;
	QApplication a( argc, argv );

	locale = QLocale::system().name();

	QStringList dirs;
	dirs    << getPrefix()
		<< "/usr/local/share/qt4/translations/"
		<< "/usr/share/qt4/translations/"
		<< "/usr/share/qt/translations/"
		<< ".";

	foreach(QString dir, dirs) {
		if (qtTr.load(QString("qt_%1").arg(locale), dir)) {
			break;
		}
	}
	xcaTr.load(QString("xca_%1").arg(locale), getPrefix());

	a.installTranslator(&qtTr);
	a.installTranslator(&xcaTr);

#ifdef Q_WS_MAC
	QStringList libp = a.libraryPaths();
	libp.prepend(a.applicationDirPath() + "/../Plugins");
	a.setLibraryPaths(libp);
#endif
	mw = new MainWindow(NULL);
	mw->read_cmdline();
	if (mw->exitApp == 0) {
		mw->show();
		ret = a.exec();
	}

	delete mw;

	pkictr =  pki_base::get_pki_counter();
	if (pkictr)
		printf("PKI Counter (%d)\n", pkictr);

	return ret;
}
