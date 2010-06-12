/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __VALIDITY_H
#define __VALIDITY_H

#include <QtGui/QDateTimeEdit>
#include <lib/asn1time.h>

class Validity : public QDateTimeEdit
{
    Q_OBJECT

  public:
	Validity( QWidget* parent);
	~Validity();
	a1time getDate() const;
	void setDate(const a1time &t, int midnight = 0);
  public slots:
	void setNow();

};

#endif
