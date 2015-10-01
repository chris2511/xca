/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __CLICKLABEL_H
#define __CLICKLABEL_H

#include <QLabel>

class QMouseEvent;

class DoubleClickLabel : public QLabel
{
  Q_OBJECT

	QString clicktext;
  public:
	DoubleClickLabel(QWidget *parent) : QLabel(parent) { }
	void setClickText(QString s);

  protected:
	void mouseDoubleClickEvent ( QMouseEvent * e );

  signals:
	void doubleClicked(QString text);
};

class ClickLabel : public DoubleClickLabel
{
  Q_OBJECT

  public:
	ClickLabel(QWidget *parent);
	void setRed();
	void setGreen();
	void disableToolTip();

  protected:
	void setColor(const QColor &col);
};

class CopyLabel : public DoubleClickLabel
{
  Q_OBJECT

  public:
	CopyLabel(QWidget *parent);
};

#endif
