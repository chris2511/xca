/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "base.h"
#include <time.h>
#include "asn1time.h"
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <qobject.h>

a1time::a1time()
{
	time = ASN1_GENERALIZEDTIME_new();
	now();
}

a1time::a1time(const ASN1_TIME *a)
{
	time = NULL;
	set(a);
}

a1time::a1time(const a1time &a)
{
	time = NULL;
	set(a.time);
}

a1time::~a1time()
{
	ASN1_TIME_free(time);
}

ASN1_TIME *a1time::get() const
{
	return M_ASN1_TIME_dup(time);
}

ASN1_TIME *a1time::get_utc() const
{
	return toUTCtime();
}

a1time &a1time::set(const ASN1_TIME *a)
{
	if (a == NULL) {
		set((time_t)0);
	}
	else {
		ASN1_TIME *siko = time;
		time = ASN1_TIME_to_generalizedtime((ASN1_TIME *)a, &siko);
		if (!time) {
			if (siko) ASN1_TIME_free(siko);
			time=M_ASN1_TIME_dup(a);
		}
	}
	return *this;
}

a1time &a1time::set(time_t t)
{
	ASN1_GENERALIZEDTIME_set(time, t);
	return *this;
}

a1time &a1time::set(int y, int mon, int d, int h, int m, int s)
{
	QString gt;
	gt.sprintf("%04d%02d%02d%02d%02d%02dZ",	y, mon, d, h, m ,s);
	return set(gt);
}

QString a1time::toPretty() const
{
        if (!time)
		return QString();
	if (isUndefined())
		return QObject::tr("Undefined");

        char buf[200];
        BIO * bio = BIO_new(BIO_s_mem());
        ASN1_TIME_print(bio, time);
        BIO_gets(bio, buf, 200);
        BIO_free(bio);
        return QString(buf);
}

QString a1time::toPlain() const
{
	QString t;
        if (time) {
		t = QString::fromAscii((char*)time->data, time->length);
	}
	return t;
}

QString a1time::toSortable() const
{
	int g;
	struct tm tm;
	QLatin1Char c('0');

	if (!time)
		 return QString();
        if (ymdg(&tm, &g)) {
                // openssl_error("time error");
        }

        return QString("%1-%2-%3 %4").
		arg(tm.tm_year, 4, 10, c).
		arg((unsigned)tm.tm_mon +1, 2, 10, c).
		arg((unsigned)tm.tm_mday, 2, 10, c).
		arg(g==1 ? "GMT" : "");
}

a1time &a1time::set(const QString &s)
{
	const char *x = s.toAscii();
	ASN1_GENERALIZEDTIME_set_string(time, (char*)x);
	return *this;
}

/* As defined in rfc-5280  4.1.2.5 */
#define UNDEFINED_DATE "99991231235959Z"

void a1time::setUndefined()
{
	ASN1_GENERALIZEDTIME_set_string(time, UNDEFINED_DATE);
}

bool a1time::isUndefined() const
{
	return QString::fromAscii((char*)time->data, time->length) ==
			UNDEFINED_DATE;
}

int a1time::ymdg(int *y, int *m, int *d, int *h, int *M, int *s, int *g) const
{
        char *v;
        int i;
        *y=0, *m=0, *d=0, *g=0;
        if (!time) return 1;
        i=time->length;
        v=(char *)time->data;

        if (i < 14) return 1; /* it is at least 10 digits */
        if (v[i-1] == 'Z') *g=1;
        for (i=0; i<14; i++)
                if ((v[i] > '9') || (v[i] < '0')) return 1;
        *y= (v[0]-'0')*1000+(v[1]-'0')*100+(v[2]-'0')*10+(v[3]-'0');
        *m= (v[4]-'0')*10+(v[5]-'0');
        if ((*m > 12) || (*m < 1)) return 1;
        *d= (v[6]-'0')*10+(v[7]-'0');
        if ((*d > 31) || (*d < 1)) return 1;
        *h= (v[8]-'0')*10+(v[9]-'0');
        if ((*h > 23) || (*h < 0)) return 1;
        *M= (v[10]-'0')*10+(v[11]-'0');
        if ((*M > 59) || (*M < 0)) return 1;
        *s= (v[12]-'0')*10+(v[13]-'0');
        if ((*s > 59) || (*s < 0)) return 1;
        return 0;
}

int a1time::ymdg(struct tm *tm, int *g) const
{
	int ret, gl;

	if (!g)
		g = &gl;
	ret = ymdg(&tm->tm_year, &tm->tm_mon, &tm->tm_mday,
		   &tm->tm_hour, &tm->tm_min, &tm->tm_sec, g);
	tm->tm_mon--;
	tm->tm_year -= 1900;
	return ret;
}

a1time &a1time::now(int delta)
{
	X509_gmtime_adj(time, delta);
	return *this;
}

a1time &a1time::operator = (const a1time &a)
{
	set(a.time);
	return *this;
}

bool a1time::operator > (const a1time &a)
{
	return (ASN1_STRING_cmp(time, a.time) == 1);
}

bool a1time::operator < (const a1time &a)
{
	return (ASN1_STRING_cmp(time, a.time) == -1);
}

bool a1time::operator == (const a1time &a)
{
	return (ASN1_STRING_cmp(time, a.time) == 0);
}

bool a1time::operator != (const a1time &a)
{
	return (ASN1_STRING_cmp(time, a.time) != 0);
}

unsigned char *a1time::d2i(const unsigned char *p, int size)
{
	if (time)
		ASN1_TIME_free(time);
	time = D2I_CLASH(d2i_ASN1_TIME, NULL, &p, size);
	return (unsigned char *)p;
}

unsigned char *a1time::i2d(unsigned char *p)
{
	unsigned char *mp = p;
	i2d_ASN1_TIME(time, &mp);
	return mp;
}

int a1time::derSize() const
{
	return i2d_ASN1_TIME(time, NULL);
}


ASN1_UTCTIME *a1time::toUTCtime() const
{
	ASN1_UTCTIME *ret;
	int year=0,i ;
	// if (!ASN1_TIME_check(t)) return NULL;
	for (i=0; i<4; i++) {
		year *= 10;
		year += time->data[i] - '0';
	}
	if (year > 2049 || year <1950)
		return NULL;

	if (!(ret = ASN1_UTCTIME_new ()))
		return NULL;

	/* If already UTC Time just copy across */
	if (time->type == V_ASN1_UTCTIME) {
		if(!ASN1_STRING_set(ret, time->data, time->length))
			return NULL;
		return ret;
	}

	/* copy w/o 19 or 20 */
	if (!ASN1_STRING_set(ret, time->data+2, time->length - 2))
		return NULL;

	return ret;
}
