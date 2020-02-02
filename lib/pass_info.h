/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PASS_INFO_H
#define __PASS_INFO_H

#include <QString>
#include <QObject>
#include <QApplication>

class QWidget;

class pass_info: public QObject
{
		Q_OBJECT
   private:
	QString title;
	QString description;
	QWidget *widget;
	QString type;
	QString pixmap;

   public:
	pass_info(const QString &t, const QString &d, QWidget *w = NULL);
	QString getTitle()
	{
		return title;
	}
	QString getDescription()
	{
		return description;
	}
	QWidget *getWidget()
	{
		if (!widget)
			widget = qApp->activeWindow();
		return widget;
	}
	QString getType()
	{
		return type;
	}
	QString getImage()
	{
		return pixmap;
	}
	void setTitle(QString t)
	{
		title = t;
	}
	void setDescription(QString d)
	{
		description = d;
	}
	void setWidget(QWidget *w)
	{
		widget = w;
	}
	void setPin();
};

#endif
