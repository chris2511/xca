/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <signal.h>
#include <QApplication>
#include <QClipboard>
#include <QTranslator>
#include <QTextCodec>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QDebug>
#include <openssl/rand.h>
#include "widgets/MainWindow.h"
#include "widgets/OpenDb.h"
#include "lib/func.h"
#include "lib/db.h"
#include "lib/main.h"
#include "lib/entropy.h"
#if defined(Q_OS_WIN32)
//For the segfault handler
#include <windows.h>
#endif

QLocale XCA_application::lang = QLocale::system();
QFont XCA_application::tableFont;
QList<QLocale> XCA_application::langAvail;

void XCA_application::setMainwin(MainWindow *m)
{
	mainw = m;
}

bool XCA_application::languageAvailable(QLocale l)
{
	return langAvail.contains(l);
}

static QString defaultlang()
{
	return getUserSettingsDir() + QDir::separator() + "defaultlang";
}

XCA_application::XCA_application(int &argc, char *argv[])
	:QApplication(argc, argv)
{
	qtTr = NULL;
	xcaTr = NULL;
	mainw = NULL;

	QFile file(defaultlang());

	if (file.open(QIODevice::ReadOnly)) {
		lang = QLocale(QString(file.read(128)));
	}

	langAvail << QLocale::system();
	langAvail << QString("en");
	QDirIterator qmIt(getPrefix(), QStringList() << "*.qm", QDir::Files);
	while (qmIt.hasNext()) {
		XcaTranslator t;
		qmIt.next();
		QString language = qmIt.fileInfo().baseName().mid(4, -1);
		if (t.load(language, "xca", getPrefix()))
			langAvail << QLocale(language);
	}
	setupLanguage(lang);
#ifdef Q_OS_MAC
	QStringList libp = libraryPaths();
	libp.prepend(applicationDirPath() + "/../Plugins");
	setLibraryPaths(libp);
#endif

	tableFont = QFont("Courier", QApplication::font().pointSize()
#if defined (Q_OS_WIN32)
	+1
#else
	+2
#endif
	);
	installEventFilter(this);
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
#if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
		<< "/usr/local/share/qt5/translations/"
		<< "/usr/share/qt5/translations/"
#else
		<< "/usr/local/share/qt4/translations/"
		<< "/usr/share/qt4/translations/"
#endif
		<< "/usr/share/qt/translations/"
#endif
		;

	foreach(QString dir, dirs) {
		if (qtTr->load(lang, "qt", dir)) {
			break;
		}
	}
	xcaTr->load(lang, "xca", getPrefix());
	QLocale::setDefault(l);
	installTranslator(qtTr);
	installTranslator(xcaTr);
	if (mainw)
		mainw->initResolver();
}

void XCA_application::quit()
{
	if (mainw)
		mainw->close();
}

void XCA_application::switchLanguage(QAction* a)
{
	QLocale lang = a->data().toLocale();
	setupLanguage(lang);

	if (portable_app())
		return;

	QFile file(defaultlang());

	if (lang == QLocale::system()) {
		file.remove();
		return;
	}

	if (file.open(QIODevice::WriteOnly)) {
		file.write(lang.name().toUtf8());
	}
}

bool XCA_application::eventFilter(QObject *watched, QEvent *ev)
{
	static int mctr;
	QMouseEvent *me;
	QStringList l;
	XcaTreeView *treeview;
	int key;

	switch (ev->type()) {
	case QEvent::FileOpen:
		l << static_cast<QFileOpenEvent *>(ev)->file();
		mainw->openURLs(l);
		return true;
	case QEvent::MouseMove:
	case QEvent::NonClientAreaMouseMove:
		if (mctr++ > 8) {
			me = static_cast<QMouseEvent *>(ev);
			entropy.add(me->globalX());
			entropy.add(me->globalY());
			mctr = 0;
		}
		break;
	case QEvent::KeyPress:
		key = static_cast<QKeyEvent *>(ev)->key();
		if (key < 0x100) {
			entropy.add(key);
		}
		break;
	case QEvent::MouseButtonPress:
		me = static_cast<QMouseEvent *>(ev);
		treeview = watched ?
			dynamic_cast<XcaTreeView*>(watched->parent()) : NULL;

		if ((watched == mainw || treeview) &&
		    me->button() == Qt::MidButton &&
		    QApplication::clipboard()->supportsSelection())
		{
			mainw->pastePem();
			return true;
		}
		break;
	default:
		break;
	}
	return false;
}

bool XCA_application::notify(QObject* receiver, QEvent* event)
{
	try {
		return QApplication::notify(receiver, event);
	} catch (errorEx &err) {
		mainw->Error(err);
        } catch (...) {
		qDebug() << QString("Event exception: ")
			 << receiver << event;
		abort();
        }
	return false;
}

XCA_application::~XCA_application()
{
}

char segv_data[1024];

#if defined(Q_OS_WIN32)
static LONG CALLBACK w32_segfault(LPEXCEPTION_POINTERS e)
{
	if (e->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
		if (segv_data[0]) {
			XCA_WARN(QString(segv_data));
			abort();
		}
		return EXCEPTION_CONTINUE_EXECUTION;
	} else
		return EXCEPTION_CONTINUE_SEARCH;
}
#else
static void segv_handler_gui(int)
{
	if (segv_data[0])
		XCA_WARN(QString(segv_data));
	abort();
}
#endif

int main( int argc, char *argv[] )
{
	int ret = 0;
	MainWindow *mw;
	QDir d;

#if defined(Q_OS_WIN32)
	SetUnhandledExceptionFilter(w32_segfault);
#else
	signal(SIGSEGV, segv_handler_gui);
#endif

	d.mkpath(getUserSettingsDir());

	XCA_application a(argc, argv);
	mw = new MainWindow(NULL);
	try {
		a.setMainwin(mw);
		OpenDb::checkSqLite();
		mw->read_cmdline(argc, argv);
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
	return ret;
}
