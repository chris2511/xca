


AC_INIT(xca, 0.2.4)
AC_CONFIG_SRCDIR([MainWindow.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX

# enable QTDIR if exist
if test -d "$QTDIR" ; then
	export PATH=$PATH:$QTDIR/bin
	export CPPFLAGS="$CPPFLAGS -I$QTDIR/include"
	export LDFLAGS="$LDFLAGS -L$QTDIR/lib"
	AC_MSG_NOTICE([Using QT in $QTDIR....])
else
	export CPPFLAGS="$CPPFLAGS -I/usr/include/qt -I/usr/local/include/qt"
	AC_MSG_NOTICE([QTDIR was not set, using default locations])
fi
AC_LANG(C++)
H_SSL=no
H_DB=no
AC_CHECK_HEADERS([evp.h openssl/evp.h],[H_SSL=y;break])
if test "$H_SSL" == no; then
	AC_MSG_ERROR([OpenSSL headerfiles not found])
fi
AC_CHECK_HEADERS([db_cxx.h db/db_cxx.h db3/db_cxx.h db4/db_cxx],[H_DB=y;break])
if test "$H_DB" == no; then
	AC_MSG_ERROR([Berkeley DB header files not found (Redhat 7.3 users should have a look at www.hohnstaedt.de/xca for a workaround)])
fi
AC_CHECK_HEADER([qaccessible.h])

# Checks for libraries.
AC_CHECK_LIB([crypto], [atexit], , [AC_MSG_ERROR([OpenSSL libraries not found, try installing openssl-dev or look at www.openssl.org])])
AC_CHECK_LIB([stdc++], [atexit], , [AC_MSG_ERROR([standard C++ librarie not found...])])
LDB=X
AC_CHECK_LIB([db_cxx], [atexit], ,[LDB=${LDB}y] )
AC_CHECK_LIB([db3_cxx], [atexit], ,[LDB=${LDB}y] )
AC_CHECK_LIB([db4_cxx], [atexit], ,[LDB=${LDB}y] )
if test "$LDB" == Xyyy; then
	AC_MSG_ERROR([C++ extension library to Berkeley db not found, try installing libdb_cxx-dev])
fi
LQT=y
AC_CHECK_LIB([qt], [atexit], ,[LQT=no])

AC_PATH_PROG(MOC,moc,[moc],[$PATH],,[LQT=no])
AC_PATH_PROG(UIC,uic,[uic],[$PATH],,[LQT=no])
if test "$LDB" == no; then
	AC_MSG_ERROR([QT library and tools not found, try setting $QTDIR apropriate or install qt-dev])
fi

AC_CONFIG_FILES([Makefile lib/Makefile])
AC_OUTPUT

cat << EOT
*****************************************************************
* It seems, all headers and libraries were found...             *
*                                                               *
* If you have comments, compilingproblems, bugs or suggestions, *
* don't hesitate to contact me at: christian@hohnstaedt.de      *
*                                                               *
* now type make to build the package....                        *
*****************************************************************
EOT


