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
 *	http://www.sleepycat.com
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

#include "asn1time.h"
#include <openssl/x509.h>

a1time::a1time()
{
	time = ASN1_TIME_new();
	now();
}

a1time::a1time(ASN1_TIME *a)
{
	time = M_ASN1_TIME_dup(a);
}

a1time::~a1time()
{
	ASN1_TIME_free(time);
}

void a1time::set(ASN1_TIME *a)
{
	ASN1_TIME_free(time);
	time = M_ASN1_TIME_dup(a);
}

void a1time::set(time_t t)
{
	ASN1_TIME_set(time, t);
}


QString a1time::toPretty()
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

QString a1time::toPlain()
{
        QString t = "";
        char b[15];
        if (!time) return t;
        memcpy(b, time->data, time->length);
        b[time->length] = '\0';
        t = b;
        return t;
}

QString a1time::toSortable()
{
        int y,m,d,g;
        QString t = "";
        if (!time) return t;
        if (ymdg( &y ,&m ,&d ,&g)) {
                // openssl_error("time error");
        }
        char buf[20];
        sprintf(buf, "%04d-%02d-%02d %s",y+1900,m,d,(g==1)?"GMT":"");
        t = buf;
        return t;
}

int a1time::ymdg(int *y, int *m, int *d, int *g)
{
        char *v;
        int i;
        *y=0, *m=0, *d=0, *g=0;
        if (!time) return 1;
        i=time->length;
        v=(char *)time->data;

        if (i < 10) return 1; /* it is at least 10 digits */
        if (v[i-1] == 'Z') *g=1;
        for (i=0; i<10; i++)
                if ((v[i] > '9') || (v[i] < '0')) return 1;
        *y= (v[0]-'0')*10+(v[1]-'0');
        if (*y < 50) *y+=100;
        *m= (v[2]-'0')*10+(v[3]-'0');
        if ((*m > 12) || (*m < 1)) return 1;
        *d= (v[4]-'0')*10+(v[5]-'0');
        if ((*d > 31) || (*d < 1)) return 1;
        return 0;
}

void a1time::now(int delta)
{
	X509_gmtime_adj(time, delta);
}

void a1time::operator = (const a1time &a)
{
	set(a.time);
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

unsigned char *a1time::i2d(unsigned char *p)
{
	unsigned char *mp = p;
	i2d_ASN1_TIME(time, &mp);
	return mp;
}

int a1time::derSize()
{
	return i2d_ASN1_TIME(time, NULL);
}
