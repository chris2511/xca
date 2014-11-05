AC_DEFUN([XCA_COMPILE_TEST], [

# Try to compile a little application
#####################################
CXXFLAGS="${CXXFLAGS} ${OPENSSL_CFLAGS}${QT_CFLAGS}"
LIBS="${LIBS} ${OPENSSL_LIBS}${QT_LIBS}"

AC_TRY_RUN([
#include <stdio.h>
#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <QtCore/qglobal.h>
#define C "configure: "
#define WARN C"###################### WARNING ######################\n"
int main(){
  char buf[2048] = "";
  printf(C"The Versions of the used libraries are:\n"
        C"Header:\n"
        C"\t%s 0x%lxL\n"
        C"\tQT: %s\n"
        C"Libraries:\n"
        C"\t%s\n"
        C"\tQT: %s\n",
                OPENSSL_VERSION_TEXT, OPENSSL_VERSION_NUMBER,
                QT_VERSION_STR,
                SSLeay_version(SSLEAY_VERSION),
                qVersion()
        );
  if (strcmp(QT_VERSION_STR, qVersion()))
        strcat(buf, C"The versions of the QT headers and library differ\n");
  if (strcmp(OPENSSL_VERSION_TEXT, SSLeay_version(SSLEAY_VERSION)))
        strcat(buf, C"The versions of the OpenSSL headers and library differ\n");
#ifdef OPENSSL_NO_EC
  strcat(buf, C"This OpenSSL installation has no EC cryptography support\n");
#endif
  if (*buf)
        printf(WARN "%s" WARN, buf);
  return 0;
}
], [ ], [echo "Unable to execute a freshly compiled application, maybe you have to adjust your LD_LIBRARY_PATH or /etc/ld.so.conf"], [echo "Skipping the compile test because of cross-compiling"])

])
