AC_DEFUN([XCA_COMPILE_TEST], [

# Try to compile a little application
#####################################

AC_TRY_RUN([
#include <stdio.h>
#include <string.h>
#include <ltdl.h>
#include <openssl/opensslv.h>
#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <qglobal.h>
#define C "configure: "
#define WARN C"###################### WARNING ######################\n"
int main(){
  char buf[2048] = "";
  int r = lt_dlinit();
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
  if (r)
	strcat(buf, C"lt_dlinit() returned != 0\n");
#ifdef OPENSSL_NO_EC
  strcat(buf, C"This OpenSSL installation has no EC cryptography support\n");
#else
#ifdef NID_brainpoolP160r1
  printf(C"ECC With RFC 5639 Brainpool curves enabled\n"
#if OPENSSL_VERSION_NUMBER < 0x10002001L
	C"    (Backported to " OPENSSL_VERSION_TEXT ")\n"
#endif
	);
#endif
#endif
  if (*buf)
        printf(WARN "%s" WARN, buf);
  return 0;
}
], [ ], [echo "Unable to execute a freshly compiled application, maybe you have to adjust your LD_LIBRARY_PATH or /etc/ld.so.conf"], [echo "Skipping the compile test because of cross-compiling"])

])
