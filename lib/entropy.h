/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __ENTROPY_H
#define __ENTROPY_H

#include <QString>
#include <QByteArray>
#include <QTime>

class Entropy
{
    protected:
	QString rnd;
	static QTime timer;
	static unsigned char pool[512];
	static unsigned pool_pos;
	static unsigned seed_strength;
	static int random_from_file(QString fname, unsigned amount,
					int weakness=1);
    public:
	Entropy();
	~Entropy();
	static void add(int rand);
	static void add_buf(const unsigned char *buf, int buflen);
	static int get(unsigned char *buf, int num);
	static void seed_rng();
	static unsigned strength();
};

#endif
