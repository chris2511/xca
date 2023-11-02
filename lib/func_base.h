/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __FUNC_BASE_H
#define __FUNC_BASE_H

#include <QByteArray>
#include <QMap>

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

#include "base.h"
#include "Passwd.h"
#include <openssl/asn1.h>
#include <openssl/evp.h>

#define IS_GUI_APP (is_gui_app)

class Validity;
class QPixmap;
extern bool is_gui_app;

QString getFullFilename(const QString &filename, const QString &selectedFilter);
const QStringList getLibExtensions();

QString formatHash(const QByteArray &data, QString sep = ":", int width = 2);
QString compressFilename(const QString &filename, int maxlen = 50);

QString asn1ToQString(const ASN1_STRING *str, bool quote = false);
ASN1_STRING *QStringToAsn1(QString s, int nid);

QByteArray Digest(const QByteArray &data, const EVP_MD *type);

const char *OBJ_ln2sn(const char *ln);
const char *OBJ_sn2ln(const char *sn);
const char *OBJ_obj2sn(ASN1_OBJECT *a);
QString OBJ_obj2QString(const ASN1_OBJECT *a, int no_name = 0);

extern QMap<int, QString> dn_translations;
void dn_translations_setup();
#define openssl_error_msg(x) _openssl_error(QString(x), __FILE__, __LINE__)
#define openssl_error() openssl_error_msg("")
#define ign_openssl_error() _ign_openssl_error(QString(), __FILE__, __LINE__)
void _openssl_error(const QString &txt, const char *file, int line);
bool _ign_openssl_error(const QString &txt, const char *file, int line);

QByteArray i2d_bytearray(int(*i2d)(const void*, unsigned char**), const void*);
void *d2i_bytearray(void *(*d2i)(void*, unsigned char**, long),
		QByteArray &ba);

#define I2D_VOID(a) ((int (*)(const void *, unsigned char **))(a))
#define D2I_VOID(a) ((void *(*)(void *, unsigned char **, long))(a))

QString appendXcaComment(QString current, QString msg);

/* from version.cpp */
const char *version_str(bool html);

#endif
