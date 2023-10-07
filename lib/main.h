/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __MAIN_H
#define __MAIN_H

#include <QString>

class pki_multi;

class MainWindow;
extern MainWindow *mainwin;

extern char segv_data[1024];

pki_multi *probeAnything(const QString &, int *ret = nullptr);
int exportIndex(const QString &fname, bool hierarchy);
#endif
