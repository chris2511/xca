/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __FUNC_H
#define __FUNC_H

#include <stdio.h>
#include <openssl/asn1.h>
#include <QPixmap>
#include <QByteArray>
#include <QMap>
#include "base.h"

class Validity;

QPixmap *loadImg(const char *name);
QString getPrefix();
QString getHomeDir();
QString getLibDir();
QString getDocDir();
QString getUserSettingsDir();
QString getFullFilename(const QString &filename, const QString &selectedFilter);
QStringList getLibExtensions();

QByteArray filename2bytearray(const QString &fname);
QString filename2QString(const char *fname);
QString compressFilename(QString filename, int maxlen = 50);

QString asn1ToQString(const ASN1_STRING *str, bool quote = false);
ASN1_STRING *QStringToAsn1(QString s, int nid);

const char *OBJ_ln2sn(const char *ln);
const char *OBJ_sn2ln(const char *sn);
const char *OBJ_obj2sn(ASN1_OBJECT *a);
QString OBJ_obj2QString(const ASN1_OBJECT *a, int no_name = 0);

void inc_progress_bar(int, int, void *p);

extern bool translate_dn;
extern QMap<int, QString> dn_translations;
void dn_translations_setup();
#define openssl_error(x) _openssl_error(QString(x), C_FILE, __LINE__)
#define ign_openssl_error(x) _ign_openssl_error(QString(x), C_FILE, __LINE__)
void _openssl_error(const QString txt, const char *file, int line);
bool _ign_openssl_error(const QString txt, const char *file, int line);

QByteArray i2d_bytearray(int(*i2d)(const void*, unsigned char**), const void*);
void *d2i_bytearray(void *(*d2i)(void*, unsigned char**, long),
		QByteArray &ba);
BIO *BIO_QBA_mem_buf(QByteArray &a);

#define I2D_VOID(a) ((int (*)(const void *, unsigned char **))(a))
#define D2I_VOID(a) ((void *(*)(void *, unsigned char **, long))(a))

#define QString2filename(str) filename2bytearray(str).constData()

static inline FILE *fopen_read(QString s)
{
	return fopen(QString2filename(s), "rb");
}

static inline FILE *fopen_write(QString s)
{
	return fopen(QString2filename(s), "wb");
}

#endif
