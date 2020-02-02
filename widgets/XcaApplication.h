/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __XCAAPPLICATION_H
#define __XCAAPPLICATION_H

#include <QApplication>
#include <QTranslator>
#include <QLocale>

class MainWindow;
class QAction;

class XcaTranslator : public QTranslator
{
	Q_OBJECT
public:
	XcaTranslator(QObject *p = NULL) : QTranslator(p) { }
	bool load(const QLocale &locale, const QString &filename,
		const QString &dir)
	{
		return QTranslator::load(QString("%1_%2").arg(filename)
						.arg(locale.name()), dir);
	}
};

class XcaApplication : public QApplication
{
	Q_OBJECT

private:
	MainWindow *mainw;
	XcaTranslator *qtTr;
	XcaTranslator *xcaTr;
	static QLocale lang;
	static QList<QLocale> langAvail;

public:
	XcaApplication(int &argc, char *argv[]);
	virtual ~XcaApplication();
	void setMainwin(MainWindow *m);
	void setupLanguage(QLocale lang);
	static QLocale language() { return lang; }
	static QFont tableFont;
	static bool languageAvailable(QLocale l);
	bool eventFilter(QObject *watched, QEvent *ev);
	bool notify(QObject* receiver, QEvent* event);

public slots:
	void switchLanguage(QAction* a);
	void quit();
};
#endif
