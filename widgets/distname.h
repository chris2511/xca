/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef DISTNAME_H
#define DISTNAME_H

#include <qwidget.h>
#include <qgridlayout.h>

class x509name;
class QLabel;
class QComboBox;
class QLineEdit;
class myGridlayout;

class DistName : public QWidget
{
    Q_OBJECT

  public:
	DistName(QWidget* parent);
	~DistName();
	void setX509name(const x509name &n);

  protected:
	QGridLayout* DistNameLayout;
	QLineEdit *lineEdit;
	void resizeEvent( QResizeEvent *e);

};
#endif
