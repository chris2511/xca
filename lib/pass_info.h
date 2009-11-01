/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef PASS_INFO_H
#define PASS_INFO_H

#include <qstring.h>
#include <qobject.h>
#include <qwidget.h>

#include "widgets/MainWindow.h"

class pass_info: public QObject
{
   private:
	QString title;
	QString description;
	QWidget *widget;
	QString type;
	QPixmap *pixmap;

   public:
	pass_info(QString t, QString d, QWidget *w = NULL)
	{
		title = t;
		description = d;
		widget = w;
		if (!widget)
			widget = qApp->activeWindow();
		type = tr("Password");
		pixmap = MainWindow::keyImg;
	}
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
		return widget;
	}
	QString getType()
	{
		return type;
	}
	QPixmap getImage()
	{
		return QPixmap(*pixmap);
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
	void setPin()
	{
		type = tr("PIN");
		pixmap = MainWindow::scardImg;
	}
};

#endif
