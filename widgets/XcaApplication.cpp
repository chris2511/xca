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
#include <QDir>
#include <QFile>
#include <QAction>

QFont XcaApplication::tableFont;
QList<QLocale> XcaApplication::langAvail;

void XcaApplication::setMainwin(MainWindow *m)
{
	mainw = m;
}

bool XcaApplication::languageAvailable(const QLocale &l)
{
	return langAvail.contains(l);
}

static QString defaultlang()
{
	return getUserSettingsDir() + "/defaultlang";
}

XcaApplication::XcaApplication(int &argc, char *argv[])
	: QApplication(argc, argv)
{
	QLocale lang;

	QFile file(defaultlang());

	if (file.open(QIODevice::ReadOnly)) {
		lang = QLocale(QString(file.read(128)));
	}

	langAvail << QLocale::system();
	langAvail << QLocale("en");
	QDirIterator qmIt(getI18nDir(), QStringList() << "*.qm", QDir::Files);
	while (qmIt.hasNext()) {
		XcaTranslator t;
		qmIt.next();
		QString language = qmIt.fileInfo().baseName().mid(4, -1);
		if (t.load(QLocale(language), "xca", getI18nDir()))
			langAvail << QLocale(language);
	}
	setupLanguage(lang);
#ifdef Q_OS_MACOS
	QStringList libp = libraryPaths();
	libp.prepend(applicationDirPath() + "/../Plugins");
	setLibraryPaths(libp);
#endif

	tableFont = QFont("Courier New", QApplication::font().pointSize()
#if defined (Q_OS_WIN32)
	+1
#else
	+2
#endif
	);
	installEventFilter(this);
}

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
#define QT_MAJOR "qt6"
#else
#define QT_MAJOR "qt5"
#endif

void XcaApplication::setupLanguage(const QLocale &lang)
{
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

	const QStringList dirs = {
#ifdef XCA_DEFAULT_QT_TRANSLATE
		XCA_DEFAULT_QT_TRANSLATE,
#endif
		getI18nDir(),
#ifndef WIN32
		"/usr/local/share/" QT_MAJOR "/translations/",
		"/usr/share/" QT_MAJOR "/translations/"
#endif
	};

	for (const QString &dir : dirs) {
		qDebug() << "Search QT translations for:" << lang << "in" << lang;
		if (qtTr->load(lang, "qtbase", dir)) {
			qDebug() << "Found QT translations for:" << lang << "in" << lang;
			break;
		}
	}
	xcaTr->load(lang, "xca", getI18nDir());
	QLocale::setDefault(lang);
	setLayoutDirection(lang.textDirection());
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
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
			QPoint p = me->globalPosition().toPoint();
#else
			QPoint p = me->globalPos();
#endif
			Entropy::add(p.x());
			Entropy::add(p.y());
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
		    me->button() == Qt::MiddleButton &&
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
	delete xcaTr;
	delete qtTr;
}
