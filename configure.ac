AC_INIT(xca, 0.2.13-PRE1)
AC_CONFIG_SRCDIR([MainWindow.h])
AC_CONFIG_HEADERS([config.h])


if test -z "$CFLAGS"; then
	CFLAGS=-O2
fi

# Checks for programs.
AC_PROG_CXX

AC_SUBST(ac_QTDIR)
AC_SUBST(ac_DEBUG)

# enable QTDIR if exist
if test -d "$QTDIR" ; then
	export PATH=$QTDIR/bin:$PATH
	export CPPFLAGS="$CPPFLAGS -I$QTDIR/include"
	export LDFLAGS="$LDFLAGS -L$QTDIR/lib"
	ac_QTDIR="$QTDIR"
else
	export CPPFLAGS="$CPPFLAGS -I/usr/include/qt -I/usr/local/include -I/usr/X11R6/include"
	export LDFLAGS="$LDFLAGS -L/usr/local/lib -L/usr/X11R6/lib"
	ac_QTDIR="System location"
fi

H_SSL=no
H_DB=no

AC_CHECK_HEADERS([evp.h openssl/evp.h],[H_SSL=y;break])
if test "$H_SSL" == no; then
	AC_MSG_ERROR([OpenSSL headerfiles not found])
fi


AC_LANG(C++)
AC_CHECK_HEADERS([db4/db_cxx.h db3/db_cxx.h db/db_cxx.h db_cxx.h],[H_DB=y;break])
if test "$H_DB" == no; then
	AC_MSG_ERROR([Berkeley DB header files not found (Redhat 7.3 users should have a look at www.hohnstaedt.de/xca/compfaq.html for a workaround)])
fi

AC_LANG(C)

# Checks for libraries.
AC_CHECK_LIB([crypto], [atexit], , [AC_MSG_ERROR([OpenSSL libraries not found, try installing openssl-dev or look at www.openssl.org])])
AC_CHECK_LIB([stdc++], [atexit], , [AC_MSG_ERROR([standard C++ library not found...])])
LDB=X
AC_CHECK_LIB([db4_cxx], [atexit], ,[LDB=${LDB}y] )
AC_CHECK_LIB([db3_cxx], [atexit], ,[LDB=${LDB}y] )
AC_CHECK_LIB([db_cxx], [atexit], ,[LDB=${LDB}y] )
LQT=y
AC_CHECK_LIB([qt], [atexit], ,[LQT=no])
if test "$LQT" == "no"; then
        LQT=y
	# check for FreeBSD paths
        AC_CHECK_LIB([c_r], [atexit])
        AC_CHECK_LIB([qt-mt], [atexit], ,[LQT=no])
	
fi

AC_PATH_PROG(MOC,moc,[moc],[$PATH /usr/X11R6/bin],,[LQT=no])
AC_PATH_PROG(UIC,uic,[uic],[$PATH /usr/X11R6/bin],,[LQT=no])

AC_ARG_ENABLE([printf-debug],[  --enable-printf-debug   switch on or off the printf-debugging ],
[if test "x$enableval" == "xyes"; then
	AC_DEFINE(PRINTF_DEBUG)
	ac_DEBUG=-g
fi], AC_DEFINE(PRINTF_DEBUG) )

AC_ARG_ENABLE([debug],[  --enable-debug          switch on or off debugging flag],
[if test "x$enableval" == "xyes"; then
	ac_DEBUG=-g
else
	ac_DEBUG=
fi], ) 

AC_CONFIG_FILES([Makefile lib/Makefile results lib/base.h])
AC_OUTPUT

if test "$LDB" == Xyyy; then
	AC_MSG_NOTICE([C++ extension library to Berkeley db not found, try installing libdb_cxx-dev])
fi
if test "$LQT" == "no"; then
	AC_MSG_NOTICE([QT library and tools not found, try setting $QTDIR apropriate or install qt-dev])
fi

cat results

