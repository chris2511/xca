# Process this file with autoconf to produce a configure script.


AC_INIT(xca, 0.2.2a)
AC_CONFIG_SRCDIR([MainWindow.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX

# enable QTDIR if exist
if test -d "$QTDIR" ; then
	export PATH=$PATH:$QTDIR/bin
	export CPPFLAGS="$CPPFLAGS -I$QTDIR/include"
	export LDFLAGS="$LDFLAGS -L$QTDIR/lib"
else
	export CPPFLAGS="$CPPFLAGS -I/usr/include/qt -I/usr/local/include/qt"
fi

# Checks for libraries.
AC_CHECK_LIB([crypto], [atexit])
AC_CHECK_LIB([stdc++], [atexit])
AC_CHECK_LIB([db3_cxx], [atexit])
AC_CHECK_LIB([db_cxx], [atexit])
AC_CHECK_LIB([qt], [atexit])
#AC_CHECK_LIB([qt-mt], [atexit])

AC_LANG(C++)

AC_CHECK_HEADERS(evp.h openssl/evp.h db3/db_cxx.h db/db_cxx.h db_cxx.h)

AC_PATH_PROG(MOC,moc,[moc],[$PATH])
AC_PATH_PROG(UIC,uic,[uic],[$PATH])

AC_C_CONST
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_HEADER_STDC

AC_CONFIG_FILES([Makefile lib/Makefile])
AC_OUTPUT
