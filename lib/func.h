/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __FUNC_H
#define __FUNC_H

#include <QByteArray>
#include <QMap>

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

#include "base.h"
#include "Passwd.h"

#define IS_GUI_APP (is_gui_app)

class Validity;
class MainWindow;
class QPixmap;
extern MainWindow *mainwin;
extern bool is_gui_app;

typedef struct asn1_object_st ASN1_OBJECT;
typedef struct asn1_string_st ASN1_STRING;
typedef struct evp_md_st EVP_MD;

int console_write(FILE *fp, const QByteArray &ba);
Passwd readPass();
int portable_app();
const QString getHomeDir();
const QString getLibDir();
const QString getDocDir();
const QString getUserSettingsDir();
const QString getI18nDir();

QString relativePath(QString path);
QString getFullFilename(const QString &filename, const QString &selectedFilter);
const QStringList getLibExtensions();
QString hostId();

QString formatHash(const QByteArray &data, QString sep = ":", int width = 2);
QString compressFilename(const QString &filename, int maxlen = 50);

QString asn1ToQString(const ASN1_STRING *str, bool quote = false);
ASN1_STRING *QStringToAsn1(QString s, int nid);

QByteArray Digest(const QByteArray &data, const EVP_MD *type);
QString fingerprint(const QByteArray &data, const EVP_MD *type);
void update_workingdir(const QString &file);

const char *OBJ_ln2sn(const char *ln);
const char *OBJ_sn2ln(const char *sn);
const char *OBJ_obj2sn(ASN1_OBJECT *a);
QString OBJ_obj2QString(const ASN1_OBJECT *a, int no_name = 0);

extern QMap<int, QString> dn_translations;
void dn_translations_setup();
#define openssl_error_msg(x) _openssl_error(QString(x), C_FILE, __LINE__)
#define openssl_error() openssl_error_msg("")
#define ign_openssl_error() _ign_openssl_error(QString(), C_FILE, __LINE__)
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
