/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PASSWD_H
#define __PASSWD_H

#include <QByteArray>

class Passwd: public QByteArray
{
    public:
	void cleanse();
	~Passwd();
	unsigned char *constUchar() const;
	Passwd & operator= (const char *p)
	{
		return (Passwd&)QByteArray::operator=(p);
	}
	Passwd & operator= (const QByteArray &other)
	{
		return (Passwd&)QByteArray::operator=(other);
	}
};

#endif
