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

#include "base.h"
#include "func_base.h"
#include "Passwd.h"

#define IS_GUI_APP (is_gui_app)

class Validity;
class QPixmap;
extern bool is_gui_app;

typedef struct asn1_object_st ASN1_OBJECT;
typedef struct asn1_string_st ASN1_STRING;
typedef struct evp_md_st EVP_MD;

int console_write(FILE *fp, const QByteArray &ba);
Passwd readPass();
int portable_app();
const QString getHomeDir();
QString relativePath(QString path);
const QString getLibDir();
const QString getDocDir();
const QString getUserSettingsDir();
const QString getI18nDir();

void migrateOldPaths();
QString hostId();
QString fingerprint(const QByteArray &data, const EVP_MD *type);
void update_workingdir(const QString &file);

#endif
