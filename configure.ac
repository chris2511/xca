AC_INIT([X Certificate and Key management],
	m4_esyscmd([tr -d '\n' < VERSION]),
	[christian@hohnstaedt.de],
	[xca],
	[http://xca.hohnstaedt.de])
AC_MSG_NOTICE([     ***************************************************])
AC_MSG_NOTICE([     *   ${PACKAGE_NAME} ${PACKAGE_VERSION}])
AC_MSG_NOTICE([     ***************************************************])
AC_PROG_CXX
AC_LANG(C++)
AC_CHECK_TOOL(STRIP, [strip], [:])

export PKG_CONFIG_PATH
export LD_LIBRARY_PATH

# Detect the OpenSSL libraries and header
#########################################
AC_ARG_WITH([openssl],
  AS_HELP_STRING([--with-openssl], [Select the OpenSSL installation directory]),
  [ if test -d "$withval"; then
      _OPENSSLDIR="$withval"
    else
      AC_MSG_WARN([OpenSSL directory '$withval' does not exist or is not a directory])
    fi
  ], [_OPENSSLDIR="$OPENSSLDIR"])

if test -n "${_OPENSSLDIR}" && test -d "${_OPENSSLDIR}"; then
  _OPENSSLDIR=`cd ${_OPENSSLDIR} && pwd`
  PKG_CONFIG_PATH="${_OPENSSLDIR}/lib/pkgconfig:${PKG_CONFIG_PATH}"
  LD_LIBRARY_PATH="${_OPENSSLDIR}/lib:${LD_LIBRARY_PATH}"
fi

PKG_CHECK_MODULES([OPENSSL], [libcrypto >= 0.9.8])


# Detect the Qt libraries and header
####################################
AC_ARG_WITH([qt],
  AS_HELP_STRING([--with-qt], [Select the Qt installation directory]),
  [ if test -d "$withval"; then
      _QTDIR="$withval"
    else
       AC_MSG_WARN([Qt directory '$withval' does not exist or is not a directory])
    fi
  ], [_QTDIR="${QTDIR}"])

if test -n "${_QTDIR}" && test -d "${_QTDIR}"; then
  _QTDIR=`cd ${_QTDIR} && pwd`
  PKG_CONFIG_PATH="${_QTDIR}/lib/pkgconfig:${PKG_CONFIG_PATH}"
  LD_LIBRARY_PATH="${_QTDIR}/lib:${LD_LIBRARY_PATH}"
fi

PKG_CHECK_MODULES(QT, [QtCore >= 4.6, QtCore < 5.0, QtGui >= 4.6, QtGui < 5.0], [
  QT_MOC="`pkg-config --variable=moc_location QtCore`"
  QT_UIC="`pkg-config --variable=uic_location QtCore`"
]
)

# Setup MOC UIC RCC LRELEASE with absolute PATH
if test "x${QT_MOC}" = "x"; then
  QT_MOC="`which moc-qt4 || which moc`"
fi
if test "x${QT_UIC}" = "x"; then
  QT_UIC="`which uic-qt4 || which uic`"
fi
QT_LRELEASE=`echo ${QT_MOC} | sed 's/moc/lrelease/'`
QT_RCC=`echo ${QT_MOC} | sed 's/moc/rcc/'`
if ! test -x ${QT_RCC}; then
  QT_RCC=`echo ${QT_MOC} | sed 's/moc.*/rcc/'`
fi
if ! test -x ${QT_RCC}; then
  QT_RCC="`which rcc-qt4 || which rcc`"
fi

AC_SUBST([QT_MOC])
AC_SUBST([QT_UIC])
AC_SUBST([QT_LRELEASE])
AC_SUBST([QT_RCC])

# The dyn_loader library libltdl
##################################
AC_CHECK_LIB(ltdl, lt_dlopen)
AC_CHECK_HEADER(ltdl.h)

# Just give it a try .....
##########################
XCA_COMPILE_TEST()

AX_CHECK_GNU_MAKE()

# linuxdoc application detection
##################################
AC_CHECK_PROG([LINUXDOC], [linuxdoc], ["linuxdoc"], [":"])
AC_SUBST([LINUXDOC])


TOPDIR=`cd "${srcdir}" && pwd`
AC_SUBST([TOPDIR])

test -f Makefile || ln -fs "${srcdir}/Makefile"
if test "$LINUXDOC" = ":" && test ! -f doc/xca-doc.tar.gz; then
  mkdir -p doc
  cp ${srcdir}doc/xca-doc.tar.gz doc/
  AC_MSG_WARN(['linuxdoc' not found, using pre-compiled documentation])
fi

# Setup done. Write local.h and Local.mak
############################################
AC_CONFIG_HEADERS(local.h)
AC_OUTPUT([Local.mak])
