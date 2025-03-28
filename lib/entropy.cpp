/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <stdio.h>
#include <QtGlobal>
#if !defined(Q_OS_WIN32)
#include <unistd.h>
#include <fcntl.h>
#endif

#include <QDir>
#include <QDebug>
#include <openssl/rand.h>
#include "func.h"
#include "xfile.h"
#include "entropy.h"

/* Entropy sources for XCA
 *
 * Entropy is a very important topic for key generation.
 *
 * XCA uses the following sources for entropy:
 *
 * 1) During startup
 *    RAND_poll()
 *    The OpenSSL seeding mechanism.
 *    It uses /dev/urandom where possible and the
 *    Screen content on Windows.
 *
 *    If "/dev/random" exists, it will be used for additional
 *    256bit entropy. Same is true for "/dev/hwrng"
 *
 * 2) Before any key or parameter generation a "reseeding"
 *    is done. Some say reseeding is not necessary, but
 *    all say it does not harm.
 *
 *    Entropy by Mouse and keyboard events
 *    main.cpp: bool XcaApplication::eventFilter()
 *    256bit from /dev/urandom (unix/Mac)
 *
 * 3) A .rnd state file in the XCA application directory
 *    is written on exit and read on startup.
 *    After reading it, the file will be erased to avoid replays.
 *
 * 4) When managing a token that supports C_GenerateRandom
 *    and C_SeedRandom, XCA will seed the token and in return
 *    seed himself from the token.
 */

#undef DEBUG_ENTROPY

#define pool_siz (sizeof(pool)/sizeof(pool[0]))
unsigned char Entropy::pool[512];
unsigned Entropy::pool_pos = 0;
QElapsedTimer Entropy::timer;
unsigned Entropy::seed_strength = 0;

QString Entropy::makeSalt(void)
{
	QString s = "T";
	unsigned char rand[8];

	Entropy::get(rand, sizeof rand);
	for (unsigned i=0; i< sizeof rand; i++)
		s += QString("%1").arg(rand[i], 2, 16, QChar('0'));
	return s;
}


void Entropy::add(int rand)
{
	unsigned char entropy = (rand ^ timer.elapsed()) & 0xff;
	pool[pool_pos++ % pool_siz] = entropy;
}

void Entropy::add_buf(const unsigned char *buf, int buflen)
{
	RAND_seed(buf, buflen);
	seed_strength += buflen;
}

int Entropy::get(unsigned char *buf, int num)
{
	seed_rng();
	return RAND_bytes(buf, num);
}

void Entropy::seed_rng()
{
	if (pool_pos > pool_siz)
		pool_pos = pool_siz;

	RAND_seed(pool, pool_pos);
	seed_strength += pool_pos;

	random_from_file("/dev/urandom", 32);
#ifdef DEBUG_ENTROPY
	{
		QDebug dbg = qDebug();
		dbg << QString("Seeding %1 bytes:").arg(pool_pos);
		for (unsigned i=0; i<pool_pos; i++)
			dbg << pool[i];
	}
	qDebug("Entropy strength: %d", seed_strength);
#endif
	pool_pos = 0;
}

int Entropy::random_from_file(QString fname, unsigned amount, int weakness)
{
#if !defined(Q_OS_WIN32)
	char buf[256];
	int fd, sum;

	/* OpenSSL: RAND_load_file() is blocking
	 * and does not support wchar_t */
	XFile file(fname);
	try {
		file.open_read();
	} catch (errorEx &e) {
		qDebug() << "random_from_file" << fname << e.getString();
		return 0;
	}
	fd = file.handle();
	if (fd == -1)
		return 0;
	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
		return 0;
	for (sum=0; amount > 0;) {
		int len = read(fd, buf, amount > sizeof buf ?
					sizeof buf : amount);
		if (len > 0) {
			RAND_seed(buf, len);
			seed_strength += len / weakness;
			amount -= len;
			sum += len;
		}
		if (len == -1) {
			if (errno != EWOULDBLOCK)
				qWarning("Error '%s' while reading '%s'\n",
					strerror(errno), CCHAR(fname));
			len = 0;
		}
		if (len == 0)
			break;
	}
#ifdef DEBUG_ENTROPY
	qDebug("Entropy from file '%s' = %d bytes", CCHAR(fname), sum);
#endif
	return sum;
#else
	(void)fname;
	(void)amount;
	(void)weakness;
	return 0;
#endif
}

unsigned Entropy::strength()
{
	return seed_strength;
}

Entropy::Entropy()
{
	timer.start();

	rnd = getUserSettingsDir() + "/.rnd";
	random_from_file(rnd, 1024, 128);
	QFile::remove(rnd); // don't use it again

	RAND_poll();
	seed_strength += 8;

	random_from_file("/dev/random", 32);
	random_from_file("/dev/hwrng", 32);
}

Entropy::~Entropy()
{
	unsigned char buf[1024];

	if (RAND_bytes(buf, sizeof buf) == 1) {
		XFile file(rnd);
		try {
			file.open_key();
			file.write((char*)buf, sizeof buf);
		} catch (errorEx &e) {
			qDebug() << "random_from_file" << rnd
				 << e.getString();
		}
		file.close();
	}
	memset(buf, 0, sizeof buf);
#ifdef DEBUG_ENTROPY
	qDebug("Seed strength: %d", seed_strength);
#endif
}
