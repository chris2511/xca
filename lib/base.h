/* base definitions */

#ifndef BASE_H
#define BASE_H

#define XCA_TITLE "X Certificate and Key management"

#include <qglobal.h>

#if QT_VERSION >= 0x030000
#if QT_VERSION >= 0x040000
#define qt4
#define QListView Q3ListView
#define QListViewItem Q3ListViewItem
#define QListViewItemIterator Q3ListViewItemIterator
#else
#define qt3
#endif
#endif

#ifdef WIN32
#include <windows.h>
#endif  

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x00908000L
#define D2I_CLASH(f, a, PP, s) f(a,PP,s)
#define D2I_CLASHT(f, t, a, PP, s) f(t,a,PP,s)
#else
#define D2I_CLASH(f, a, PP, s) f(a,(unsigned char **)PP,s)
#define D2I_CLASHT(f, t, a, PP, s) f(t,a,(unsigned char **)PP,s)
#endif

#endif
