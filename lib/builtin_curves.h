/*
 * Copyright (C) 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __BUILTIN_EC_CURVES_H
#define __BUILTIN_EC_CURVES_H

#include <QtCore/QString>
#include <QtCore/QList>

#include "base.h"

#define CURVE_X962  1
#define CURVE_OTHER 2

class builtin_curve
{
    public:
	int nid;
	QString comment;
	unsigned order_size;
	int flags;
	/* type:
	 * NID_X9_62_prime_field
	 * NID_X9_62_characteristic_two_field
	 */
	int type;
	builtin_curve(int n, QString c, int s, int f, int t) {
		nid = n;
		comment = c;
		order_size = s;
		flags = f;
		type = t;
	};
};

class builtin_curves: public QList<builtin_curve>
{
    public:
	builtin_curves();
};

#endif
