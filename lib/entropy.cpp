/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <QFile>
#include <QDir>
#include <QDebug>
#include <openssl/rand.h>
#include "func.h"
#include "entropy.h"
#include "openssl_compat.h"

#if defined(Q_OS_WIN32)
/* On Windows O_NONBLOCK is an unknown concept :-)
 * We don't need it anyway on that platform ....
 */
#define O_NONBLOCK 0
#endif

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
 *    is done. Some say reseeding is not neccessary, but
 *    all say it does not harm.
 *
 *    Entropy by Mouse and keyboard events
 *    main.cpp: bool XCA_application::eventFilter()
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
QTime Entropy::timer;
unsigned Entropy::seed_strength = 0;

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

#if !defined(Q_OS_WIN32)
	random_from_file("/dev/urandom", 32);
#endif
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
	char buf[256];
	int fd, sum;
	QByteArray ba = filename2bytearray(fname);
	const char *file = ba.constData();

	/* OpenSSL: RAND_load_file() is blocking */
	fd = open(file, O_RDONLY | O_NONBLOCK);

	if (fd == -1)
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
					strerror(errno), file);
			len = 0;
		}
		if (len == 0)
			break;
	}
	close(fd);
#ifdef DEBUG_ENTROPY
	qDebug("Entropy from file '%s' = %d bytes", file, sum);
#endif
	return sum;
}

unsigned Entropy::strength()
{
	return seed_strength;
}

Entropy::Entropy()
{
	timer.start();

	rnd = getUserSettingsDir() + QDir::separator() + ".rnd";
	random_from_file(rnd, 1024, 128);
	QFile::remove(rnd); // don't use it again

	RAND_poll();
	seed_strength += 8;

#if !defined(Q_OS_WIN32)
	random_from_file("/dev/random", 32);
	random_from_file("/dev/hwrng", 32);
#endif
}

Entropy::~Entropy()
{
	QByteArray ba = filename2bytearray(rnd);
	RAND_write_file(ba.constData());
#ifdef DEBUG_ENTROPY
	qDebug("Seed strength: %d", seed_strength);
#endif
}
