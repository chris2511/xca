/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QtGui/QApplication>
#include <QtCore/QTranslator>
#include <QtCore/QTextCodec>
#include <QtCore/QDir>
#include "widgets/MainWindow.h"
#include "lib/func.h"
#ifdef WIN32
#include <windows.h>
#endif

class XCA_application : public QApplication
{
	MainWindow *mainw;
	QTranslator qtTr;
	QTranslator xcaTr;

public:
	XCA_application(int &argc, char *argv[]);
	void setMainwin(MainWindow *m)
	{
		mainw = m;
	}
protected:
	bool event(QEvent *ev);
};

XCA_application::XCA_application(int &argc, char *argv[])
	:QApplication(argc, argv)
{
	QString locale;
	QStringList dirs;

	locale = QLocale::system().name();

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
		if (qtTr.load(QString("qt_%1").arg(locale), dir)) {
			break;
		}
	}
	xcaTr.load(QString("xca_%1").arg(locale), getPrefix());

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
		QString file = static_cast<QFileOpenEvent *>(ev)->file();
		if (mainw)
			mainw->importAnything(file);

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
