/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __CLICKLABEL_H
#define __CLICKLABEL_H

#include <QtGui/QLabel>

class QMouseEvent;

class ClickLabel : public QLabel
{
  Q_OBJECT

  public:
	ClickLabel(QWidget *parent);
	void setRed();
	void setGreen();
	void disableToolTip();

  protected:
	void mouseDoubleClickEvent ( QMouseEvent * e );
	void setColor(const QColor &col);

  signals:
	void doubleClicked(QString text);
};

class CopyLabel : public QLabel
{
  Q_OBJECT

  public:
	CopyLabel(QWidget *parent);
};

#endif
