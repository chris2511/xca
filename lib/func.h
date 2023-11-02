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

#include <openssl/asn1.h>
#include <openssl/evp.h>

#define IS_GUI_APP (is_gui_app)

class Validity;
class QPixmap;
extern bool is_gui_app;

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
