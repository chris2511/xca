/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "XcaApplication.h"
#include "MainWindow.h"
#include "XcaWarning.h"

#include "lib/entropy.h"

#include <QClipboard>
#include <QTextCodec>
#include <QDir>
#include <QFile>
#include <QAction>

QLocale XcaApplication::lang = QLocale::system();
QFont XcaApplication::tableFont;
QList<QLocale> XcaApplication::langAvail;

void XcaApplication::setMainwin(MainWindow *m)
{
	mainw = m;
}

bool XcaApplication::languageAvailable(QLocale l)
{
	return langAvail.contains(l);
}

static QString defaultlang()
{
	return getUserSettingsDir() + "/defaultlang";
}

XcaApplication::XcaApplication(int &argc, char *argv[])
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
	QDirIterator qmIt(getI18nDir(), QStringList() << "*.qm", QDir::Files);
	while (qmIt.hasNext()) {
		XcaTranslator t;
		qmIt.next();
		QString language = qmIt.fileInfo().baseName().mid(4, -1);
		if (t.load(language, "xca", getI18nDir()))
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
	setWindowIcon(QIcon(QPixmap(":appIcon")));
}

void XcaApplication::setupLanguage(QLocale l)
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
		<< getI18nDir()
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

	qDebug() << "Setup language: " << lang;
	foreach(QString dir, dirs) {
		if (qtTr->load(lang, "qt", dir)) {
			break;
		}
	}
	xcaTr->load(lang, "xca", getI18nDir());
	QLocale::setDefault(l);
	installTranslator(qtTr);
	installTranslator(xcaTr);
	if (mainw)
		mainw->initResolver();
}

void XcaApplication::quit()
{
	if (mainw)
		mainw->close();
}

void XcaApplication::switchLanguage(QAction* a)
{
	QLocale lang = a->data().toLocale();
	setupLanguage(lang);

	QFile file(defaultlang());

	if (lang == QLocale::system()) {
		file.remove();
		return;
	}

	if (file.open(QIODevice::WriteOnly)) {
		file.write(lang.name().toUtf8());
	}
}

bool XcaApplication::eventFilter(QObject *watched, QEvent *ev)
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
			Entropy::add(me->globalX());
			Entropy::add(me->globalY());
			mctr = 0;
		}
		break;
	case QEvent::KeyPress:
		key = static_cast<QKeyEvent *>(ev)->key();
		if (key < 0x100) {
			Entropy::add(key);
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

bool XcaApplication::notify(QObject* receiver, QEvent* event)
{
	try {
		return QApplication::notify(receiver, event);
	} catch (errorEx &err) {
		XCA_ERROR(err);
        } catch (...) {
		qWarning() << QString("Event exception: ")
			 << receiver << event;
        }
	return false;
}

XcaApplication::~XcaApplication()
{
}

