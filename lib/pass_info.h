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

class pass_info: public QObject
{
   private:
	QString title;
	QString description;
	QWidget *widget;

   public:
	pass_info(QString t, QString d, QWidget *w = NULL);
	QString getTitle();
	QString getDescription();
	QWidget *getWidget();

	void setTitle(QString t);
	void setDescription(QString d);
	void setWidget(QWidget *w);
};

#endif
