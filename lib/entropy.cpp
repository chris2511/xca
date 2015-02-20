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
#include <openssl/rand.h>
#include "func.h"
#include "entropy.h"

#ifdef WIN32
/* On Windows O_NONBLOCK is an unknown concept :-)
 * We don't need it anyway on that platform ....
 */
#define EWOULDBLOCK EAGAIN
#define O_NONBLOCK 0
#endif

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

#ifdef WIN32
	if (seed_strength < 16) {
		RAND_screen();
		seed_strength += 8;
	}
#else
	random_from_file("/dev/random", 64);
	random_from_file("/dev/hwrng", 64);
#endif
#ifdef DEBUG_ENTROPY
	fprintf(stderr, "Seeding %d bytes:", pool_pos);
	for (unsigned i=0; i<pool_pos; i++)
		fprintf(stderr, " %02x", pool[i]);
	fprintf(stderr, "\nEntropy strength: %d\n", seed_strength);
#endif
	pool_pos = 0;
}

int Entropy::random_from_file(QString fname, unsigned amount, int weakness)
{
	char buf[256];
	const char *file;
	int fd, sum;
	QByteArray ba;

	ba = filename2bytearray(fname);
	file = ba.constData();

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
	fprintf(stderr, "Entropy from file '%s' = %d bytes\n", file, sum);
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
}

Entropy::~Entropy()
{
	QFile f(rnd);

	if (f.open(QIODevice::ReadWrite)) {
		unsigned char buf[1024];
		seed_rng();
		f.setPermissions(QFile::ReadOwner|QFile::WriteOwner);
		RAND_pseudo_bytes(buf, sizeof buf);
                f.write((char*)buf, sizeof buf);
		f.close();
	}
#ifdef DEBUG_ENTROPY
	fprintf(stderr, "Seed strength: %d\n", seed_strength);
#endif
}
