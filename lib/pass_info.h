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

#include "lib/exception.h"

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
	enum open_result result;

   public:
	pass_info(const QString &t, const QString &d, QWidget *w = NULL);
	QString getTitle() const
	{
		return title;
	}
	QString getDescription() const
	{
		return description;
	}
	QWidget *getWidget()
	{
		if (!widget)
			widget = qApp->activeWindow();
		return widget;
	}
	QString getType() const
	{
		return type;
	}
	QString getImage() const
	{
		return pixmap;
	}
	enum open_result getResult() const
	{
		return result;
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
	void setResult(enum open_result r)
	{
		result = r;
	}
	void setPin();
};

#endif
