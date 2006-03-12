/* vi: set sw=4 ts=4: */
/*
 * Copyright (C) 2001 Christian Hohnstaedt.
 *
 *  All rights reserved.
 *
 *
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  - Neither the name of the author nor the names of its contributors may be 
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This program links to software with different licenses from:
 *
 *	http://www.openssl.org which includes cryptographic software
 * 	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.trolltech.com
 * 
 *
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$
 *
 */                           

#include "base.h"
#include "asn1time.h"
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

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
	char *p;
	if (mon < 1 || mon > 12 ||
	    d < 1 || d > 31 ||
	    h < 0 || h >23 ||
	    m < 0 || m > 59 ||
	    s < 0 || s > 59 ) {
	}
	if (time->length < 16) {
		p = (char *)OPENSSL_malloc(20);
		if (p == NULL) goto this_err;
		if (time->data != NULL)
			OPENSSL_free(time->data);
		time->data=(unsigned char *)p;
	}
	
	
	time->length = sprintf((char *)time->data, "%04d%02d%02d%02d%02d%02dZ",
		       y, mon, d, h, m ,s);
	time->type=V_ASN1_GENERALIZEDTIME;
	return *this;
this_err:
	ASN1err(ASN1_F_D2I_ASN1_GENERALIZEDTIME,ASN1_R_INVALID_TIME_FORMAT);
	return *this;
}


QString a1time::toPretty() const
{
        QString t = "";
        if (!time) return t;
        BIO * bio = BIO_new(BIO_s_mem());
        char buf[200];
        ASN1_TIME_print(bio, time);
        BIO_gets(bio, buf, 200);
        t = buf;
        BIO_free(bio);
        return t;
}

QString a1time::toPlain() const
{
        QString t = "";
        char b[15];
        if (!time) return t;
        memcpy(b, time->data, time->length);
        b[time->length] = '\0';
        t = b;
        return t;
}

QString a1time::toSortable() const
{
        int y,m,d,g;
        QString t = "";
        if (!time) return t;
        if (ymdg( &y ,&m ,&d ,&g)) {
                // openssl_error("time error");
        }
        char buf[20];
        sprintf(buf, "%04d-%02d-%02d %s",y,m,d,(g==1)?"GMT":"");
        t = buf;
        return t;
}

a1time &a1time::set(const QString &s)
{
	const char *x = s.toAscii();
	ASN1_GENERALIZEDTIME_set_string(time, (char*)x);
	return *this;
}

int a1time::ymdg(int *y, int *m, int *d, int *g) const
{
	int h, M, s;
	return ymdg(y,m,d, &h, &M, &s, g);
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

bool const a1time::operator > (const a1time &a)
{
	return (ASN1_STRING_cmp(time, a.time) == 1);
}

bool const a1time::operator < (const a1time &a)
{
	return (ASN1_STRING_cmp(time, a.time) == -1);
}

bool const a1time::operator == (const a1time &a)
{
	return (ASN1_STRING_cmp(time, a.time) == 0);
}

bool const a1time::operator != (const a1time &a)
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
		for (i=0; i<4; i++){
			year *= 10;
			year += time->data[i] - '0';
		}
		if (year > 2049 || year <1950)
			return NULL;

        if (!(ret = ASN1_UTCTIME_new ()))
        	return NULL;

        /* If already UTC Time just copy across */
        if (time->type == V_ASN1_UTCTIME)
                {
                if(!ASN1_STRING_set(ret, time->data, time->length))
                        return NULL;
                return ret;
                }
		
		/* copy w/o 19 or 20 */
        if (!ASN1_STRING_set(ret, time->data+2, time->length - 2))
                return NULL;

        return ret;
        }
 
/* this was happily copied from OpenSSL 0.9.7 
 * and is used if linking against 0.9.6
 */

#if OPENSSL_VERSION_NUMBER < 0x00907000L
/* Convert an ASN1_TIME structure to GeneralizedTime */
ASN1_GENERALIZEDTIME *a1time::ASN1_TIME_to_generalizedtime(ASN1_TIME *t, ASN1_GENERALIZEDTIME **out)
        {
        ASN1_GENERALIZEDTIME *ret;
        char *str;

        // if (!ASN1_TIME_check(t)) return NULL;

        if (!out || !*out)
                {
                if (!(ret = ASN1_GENERALIZEDTIME_new ()))
                        return NULL;
                if (out) *out = ret;
                }
        else ret = *out;

        /* If already GeneralizedTime just copy across */
        if (t->type == V_ASN1_GENERALIZEDTIME)
                {
                if(!ASN1_STRING_set(ret, t->data, t->length))
                        return NULL;
                return ret;
                }

        /* grow the string */
        if (!ASN1_STRING_set(ret, NULL, t->length + 2))
                return NULL;
        str = (char *)ret->data;
        /* Work out the century and prepend */
        if (t->data[0] >= '5') strcpy(str, "19");
        else strcpy(str, "20");

        strncat(str, (char *)t->data, t->length);

        return ret;
        }
#endif                                                                              
