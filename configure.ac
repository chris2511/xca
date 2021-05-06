AC_INIT([X Certificate and Key management],
	m4_esyscmd([tr -d '\n' < VERSION]),
	[christian@hohnstaedt.de],
	[xca],
	[http://xca.hohnstaedt.de])

ITERATION="$(cd "$srcdir" && git rev-list --count RELEASE.${PACKAGE_VERSION}..HEAD)"
XCA_VERSION=$(IFS='.'; set - $PACKAGE_VERSION; echo $1.$2.$(($ITERATION+$3)))

AC_MSG_NOTICE([     ***************************************************])
AC_MSG_NOTICE([     *   ${PACKAGE_NAME} ${XCA_VERSION}])
AC_MSG_NOTICE([     ***************************************************])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CXX
AC_LANG(C++)
AC_CHECK_TOOL(STRIP, [strip], [:])
AC_CHECK_TOOL(WINDRES, [windres], [:])

VERSIONHASH="$(echo "${XCA_VERSION}" | shasum | cut -b -12)"
AC_SUBST([VERSIONHASH])
AC_SUBST([XCA_VERSION])
AC_DEFINE_UNQUOTED([XCA_VERSION], [ "${XCA_VERSION}" ],
		[ XCA Version string with calculated patch level])

AC_ARG_WITH([macos-version],
  AS_HELP_STRING([--with-macos-version], [Select macOS minimum SDK version]),
  [ MACOS_VERSION="$withval"
    CXXFLAGS="${CXXFLAGS} -mmacosx-version-min=$MACOS_VERSION"
    case "$withval" in
	10.10) EXTRA_VERSION=-Yosemite ;;
	10.11) EXTRA_VERSION=-El-Capitan ;;
	10.12) EXTRA_VERSION=-Sierra ;;
	10.13) EXTRA_VERSION=-High-Sierra ;;
	10.14) EXTRA_VERSION=-Mojave ;;
	10.15) EXTRA_VERSION=-Catalina ;;
	11.00) EXTRA_VERSION=-Big-Sur ;;
	*) echo "Unknown macOS Version $withval"
	   exit 1 ;;
    esac
    MACOS_VERSION3="${MACOS_VERSION}.0"
  ]
)
AC_SUBST([EXTRA_VERSION])
AC_SUBST([MACOS_VERSION])
AC_SUBST([MACOS_VERSION3])

if test -d "$INSTALL_DIR"; then
  AC_MSG_NOTICE([Using INSTALL_DIR $INSTALL_DIR])
  test -d "${INSTALL_DIR}/include" && CXXFLAGS="${CXXFLAGS} -I${INSTALL_DIR}/include"
  test -d "${INSTALL_DIR}/lib" && LIBS="${LIBS} -L${INSTALL_DIR}/lib"
fi

case "$(${CXX} -dumpmachine)" in
  *apple-darwin*)
    HOST=DARWIN
    CXXFLAGS="${CXXFLAGS} -pipe -gdwarf-2"
    LIBS="${LIBS} -framework IOKit -framework CoreFoundation"
    BREW_PREFIX="$(brew --prefix)"
    if test "$BREW_PREFIX"; then
      PKG_CONFIG_PATH="$(find ${BREW_PREFIX}/Cellar -name 'pkgconfig' -type d | tr '\n' ':')${PKG_CONFIG_PATH}"
      CXXFLAGS="${CFLAGS} -I${BREW_PREFIX}/include"
      LIBS="${LIBS} -L${BREW_PREFIX}/lib"
    fi
    export DYLD_LIBRARY_PATH
    test "${MACOS_VERSION3}" || MACOS_VERSION3="$(sw_vers -productVersion)"
    ;;
  *mingw*)
    HOST=WINDOWS
    SUFFIX=".exe"
    PKG_CONFIG="$(which pkg-config) --define-prefix"
    PKG_CONFIG_LIBDIR=""
    CXXFLAGS="${CXXFLAGS} -mthreads -mwindows -mnop-fun-dllimport -Wno-strict-aliasing"
    LIBS="${LIBS} -Wl,-enable-stdcall-fixup -Wl,-enable-auto-import -Wl,-enable-runtime-pseudo-reloc -static-libgcc"
    ;;
  *linux*)
    HOST=LINUX
    ;;
  *)
    HOST=UNIX
    ;;
esac

AC_MSG_NOTICE([Compiling for host: $HOST])

AC_SUBST([HOST])
AC_SUBST([MACDEPLOYQT])
AC_SUBST([SUFFIX])
AC_SUBST([INSTALL_DIR])

export PKG_CONFIG_PATH
export LD_LIBRARY_PATH

if test "$srcdir" != "."; then
  exist=""
  for f in Local.mak local.h commithash.h; do
    test ! -r "$srcdir"/"$f" || exist="$exist $f"
  done
  if test -n "$exist"; then
    AC_ERROR([The source directory (${srcdir}) contains the file(s):$exist.
		They must be removed before building here.])
  fi
fi

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
  DYLD_LIBRARY_PATH="${_OPENSSLDIR}/lib:${DYLD_LIBRARY_PATH}"
fi

PKG_CHECK_MODULES([OpenSSL],
   [libcrypto >= 1.0.2], [ ],
   [
     OpenSSL_LIBS=" -lcrypto ";
     AC_MSG_WARN([OpenSSL pkg-config failed, using fallback defaults (${OpenSSL_LIBS})]);
   ]
)

OPENSSL_LIBS="$OpenSSL_LIBS"
OPENSSL_CFLAGS="$OpenSSL_CFLAGS"

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
  DYLD_LIBRARY_PATH="${_QTDIR}/lib:${DYLD_LIBRARY_PATH}"
fi

AC_ARG_WITH([qt-version],
  AS_HELP_STRING([--with-qt-version], [Select the Qt version]),
  [WANT_QT_VERSION="$withval"],
  [WANT_QT_VERSION=detect])

if test "${WANT_QT_VERSION}" = detect -o "${WANT_QT_VERSION}" = 5; then
  PKG_CHECK_MODULES(Qt5, [Qt5Core >= 5.0 Qt5Widgets >= 5.0 Qt5Sql >= 5.0 Qt5Help >= 5.0], [
    _QT_HOST_BINS="`pkg-config --variable=host_bins Qt5Core`"
    QT_MOC="${_QT_HOST_BINS}/moc"
    QT_UIC="${_QT_HOST_BINS}/uic"
    if test "$HOST" = "DARWIN"; then
      FRAMEDIR=`pkg-config --variable=libdir Qt5Core`
      Qt5_CFLAGS="$Qt5_CFLAGS -std=c++11 -F${FRAMEDIR} -I${FRAMEDIR}/QtCore.framework/Headers -I${FRAMEDIR}/QtGui.framework/Headers -I${FRAMEDIR}/QtWdgets.framework/Headers -I${FRAMEDIR}/QtSql.framework/Headers"
      Qt5_LDFLAGS=" -Xlinker -rpath -Xlinker ${FRAMEDIR}"
    fi
    WANT_QT_VERSION=5
    QT_VERSION=5
    QT_CFLAGS="${Qt5_CFLAGS} -fPIC"
    QT_LIBS="${Qt5_LIBS}${Qt5_LDFLAGS}"
  ],[ : ])
fi

if test "${WANT_QT_VERSION}" = detect -o "${WANT_QT_VERSION}" = 4; then
  PKG_CHECK_MODULES(Qt4, [QtCore >= 4.7 QtCore < 5.0 QtGui >= 4.7 QtGui < 5.0 QtSql >= 4.7 QtSql < 5.0 QtHelp < 5.0], [
    QT_MOC="`pkg-config --variable=moc_location QtCore`"
    QT_UIC="`pkg-config --variable=uic_location QtCore`"
    if test -n "${QT_MOC}"; then
      _QT_HOST_BINS="`dirname ${QT_MOC}`"
    fi
    if test "$HOST" = "DARWIN"; then
      FRAMEDIR=`pkg-config --variable=libdir QtCore`
      Qt4_CFLAGS="$Qt4_CFLAGS -F${FRAMEDIR} -I${FRAMEDIR}/QtCore.framework/Headers -I${FRAMEDIR}/QtGui.framework/Headers -I${FRAMEDIR}/QtSql.framework/Headers"
      Qt4_LDFLAGS=" -Xlinker -rpath -Xlinker ${FRAMEDIR}"
    fi
    WANT_QT_VERSION=4
    QT_VERSION=4
    QT_CFLAGS="${Qt4_CFLAGS}"
    QT_LIBS="${Qt4_LIBS}${Qt4_LDFLAGS}"
  ],[ : ])
fi

if test -z "${QT_VERSION}"; then
    if test -z "$DARWIN"; then
      QT_LIBS=" -lQtCore -lQtGui "
    else
      _QT_HOST_BINS="${_QTDIR}/bin"
      QT_MOC="${_QT_HOST_BINS}/moc"
      QT_UIC="${_QT_HOST_BINS}/uic"
      FRAMEDIR=${_QTDIR}/lib
      QT_LIBS=" -framework QtGui -framework QtCore -framework QtWidgets -framework QtSql -Xlinker -rpath -Xlinker ${FRAMEDIR}"
      QT_CFLAGS="-std=c++11 -F${FRAMEDIR} -I${FRAMEDIR}/QtCore.framework/Headers -I${FRAMEDIR}/QtGui.framework/Headers -I${FRAMEDIR}/QtCore.framework/Headers -I${FRAMEDIR}/QtWidgets.framework/Headers -I${FRAMEDIR}/QtSql.framework/Headers"
    fi
    AC_MSG_WARN([Qt pkg-config failed, using fallback defaults (${QT_LIBS})]);
fi

QT_DIR="$_QTDIR"
# Delete trailing d (Debug) from Qt libs (@<:@ == [)  (@:>@ == ])
QT_LIBS="$(echo " $QT_LIBS " | sed 's/-lQt\(@<:@^ @:>@*\)d\s/-lQt\1 /g')"

AC_SUBST([QT_CFLAGS])
AC_SUBST([QT_LIBS])
AC_SUBST([QT_DIR])

# Setup MOC UIC RCC LRELEASE LCONVERT with absolute PATH
if test ! -x "${QT_MOC}"; then
  QT_MOC="`which moc-qt${QT_VERSION} || which moc`"
fi
if test ! -x "${QT_UIC}"; then
  QT_UIC="`which uic-qt${QT_VERSION} || which uic`"
fi

QT_BIN_PATH="${_QT_HOST_BINS}:$PATH"

AC_PATH_PROG([QT_LRELEASEQT], [lrelease-qt${QT_VERSION}], , [$QT_BIN_PATH])
if test "x${QT_LRELEASEQT}" = "x"; then
  AC_PATH_PROG([QT_LRELEASE], [lrelease], [lrelease], [$QT_BIN_PATH])
else
  QT_LRELEASE="$QT_LRELEASEQT"
fi

AC_PATH_PROG([QT_LCONVERTQT], [lconvert-qt${QT_VERSION}], , [$QT_BIN_PATH])
if test "x${QT_LCONVERTQT}" = "x"; then
  AC_PATH_PROG([QT_LCONVERT], [lconvert], [lconvert], [$QT_BIN_PATH])
else
  QT_LCONVERT="$QT_LCONVERTQT"
fi

AC_PATH_PROG([QT_RCCQT], [rcc-qt${QT_VERSION}], , [$QT_BIN_PATH])
if test "x${QT_RCCQT}" = "x"; then
  AC_PATH_PROG([QT_RCC], [rcc], [rcc], [$QT_BIN_PATH])
else
  QT_RCC="$QT_RCCQT"
fi

AC_PATH_PROG([QT_HELPCOLL], [qcollectiongenerator${QT_VERSION}], , [$QT_BIN_PATH])
if test "x${QT_HELPCOLL}" = "x"; then
  AC_PATH_PROG([QT_HELPCOLL], [qcollectiongenerator], [qcollectiongenerator], [$QT_BIN_PATH])
else
  QT_HELPCOLL="$QT_HELPCOLL"
fi


if test "$HOST" = "DARWIN"; then
  AC_PATH_PROG([MACDEPLOYQT], [macdeployqt], [macdeployqt], [$QT_BIN_PATH])
fi

AC_SUBST([QT_MOC])
AC_SUBST([QT_UIC])
AC_SUBST([QT_LRELEASE])
AC_SUBST([QT_LCONVERT])
AC_SUBST([QT_RCC])

# The dyn_loader library libltdl
##################################
AC_CHECK_LIB(ltdl, lt_dlopen, , [
  echo "ERROR: Library 'ltdl' with symbol 'lt_dlopen' not found."
  echo "       Try installing the package 'libltdl-dev' or 'libtool'"
  exit 1
])
AC_CHECK_HEADER(ltdl.h, , [
  echo "ERROR: Header 'ltdl.h' not found."
  echo "       Try installing the package 'libltdl-dev' or 'libtool'"
  exit 1
])

# Finally collect the compiler flags
#####################################
CXXFLAGS="${OPENSSL_CFLAGS} ${QT_CFLAGS} ${CXXFLAGS}"
LIBS="${OPENSSL_LIBS} ${QT_LIBS} -lstdc++ ${LIBS}"

# Just give it a try .....
##########################

XCA_COMPILE_TEST()

AX_CHECK_GNU_MAKE()

# linuxdoc application detection
##################################
AC_CHECK_PROGS([DOCTOOL], [sphinx-build])
AC_SUBST([DOCTOOL])

AC_ARG_ENABLE([doc],
  AS_HELP_STRING([--disable-doc], [Disable documentation installation]),
  ,
  [enable_doc=yes])
if test "${enable_doc}" = "yes" &&
   test "${DOCTOOL}" &&
   test "${QT_HELPCOLL}"
then
  ENABLE_DOC=
else
  ENABLE_DOC='\#'
fi
AC_SUBST([ENABLE_DOC])

# Setup done. Write local.h and Local.mak
############################################
AC_CONFIG_HEADERS(local.h)
AC_CONFIG_LINKS(Makefile:Makefile)
AC_CONFIG_FILES([Local.mak misc/Info.plist misc/variables.wxi doc/conf.py])

AC_OUTPUT
