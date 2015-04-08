/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <stdio.h>
#include <QtCore/QFile>
#include <QtCore/QDir>
#include <openssl/rand.h>
#include "func.h"
#include "entropy.h"

#define DEBUG_ENTROPY

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
#ifdef DEBUG_ENTROPY
	fprintf(stderr, "Seeding %d bytes:", pool_pos);
	for (unsigned i=0; i<pool_pos; i++)
		fprintf(stderr, " %02x", pool[i]);
	fprintf(stderr, "\nEntropy strength: %d\n", seed_strength);
#endif
	pool_pos = 0;
}

int Entropy::random_from_file(QString fname, int amount, int weakness)
{
	QByteArray ba;
	QFile f(fname);

	if (!f.open(QIODevice::ReadOnly))
		return 0;

	ba = f.read(amount);
	f.close();
	RAND_seed(ba.constData(), ba.size());
	seed_strength += ba.size() / weakness;
#ifdef DEBUG_ENTROPY
	fprintf(stderr, "Entropy from file '%s' = %d bytes\n",
		CCHAR(fname), ba.size());
#endif
	return ba.size();
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

#ifdef WIN32
	RAND_screen();
	seed_strength += 8;
#else
	random_from_file("/dev/random", 64);
	random_from_file("/dev/hwrng", 64);
#endif
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
