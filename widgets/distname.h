/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __DISTNAME_H
#define __DISTNAME_H

#include <QWidget>
#include <QGridLayout>

class x509name;
class QLabel;
class QComboBox;
class QLineEdit;
class myGridlayout;

class DistName : public QWidget
{
    Q_OBJECT

  public:
	DistName(QWidget *parent);
	void setX509name(const x509name &n);

  protected:
	QGridLayout* DistNameLayout;
	QLineEdit *rfc2253;
	QLineEdit *namehash;
};
#endif
