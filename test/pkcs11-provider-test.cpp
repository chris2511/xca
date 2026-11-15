/* Standalone runtime test for the XCA PKCS#11 Ed25519 provider (xca-pkcs11).
 *
 * Build (adjust the Qt6 include path to your distribution):
 *   g++ -std=c++17 -I lib -I <build-dir> -I /usr/include/qt6 -I /usr/include/qt6/QtCore \
 *       test/pkcs11-provider-test.cpp lib/pkcs11_provider.cpp \
 *       -o provtest -ldl -lcrypto -lQt6Core
 *
 * Needs a PKCS#11 token with an Ed25519 key pair (label ed25519-test),
 * e.g. SoftHSM2: softhsm2-util --init-token --slot 0 --label xca-test
 * --pin 4321 --so-pin 5678, then generate the key pair (EC_EDWARDS,
 * EC_PARAMS 06 03 2B 65 70) with any PKCS#11 tool.
 * Expects a softhsm2 token initialized with user PIN 4321 containing
 * an Ed25519 key pair labeled 'ed25519-test'. */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "pkcs11_provider.h"
#include "opensc-pkcs11.h"

static void ckfail(const char *what, CK_RV rv)
{
	fprintf(stderr, "%s failed: rv=0x%08lX\n", what, (unsigned long)rv);
	exit(1);
}

int main()
{
#if !XCA_HAS_PROVIDERS
	fprintf(stderr, "provider support not compiled in\n");
	return 1;
#else
	void *dl = dlopen("/usr/lib/softhsm/libsofthsm2.so", RTLD_NOW);
	if (!dl) {
		fprintf(stderr, "dlopen: %s\n", dlerror());
		return 1;
	}
	auto getfl = (CK_C_GetFunctionList)dlsym(dl, "C_GetFunctionList");
	CK_FUNCTION_LIST_PTR fl;
	if (getfl(&fl) != CKR_OK)
		ckfail("C_GetFunctionList", CKR_GENERAL_ERROR);
	if (fl->C_Initialize(NULL) != CKR_OK)
		ckfail("C_Initialize", CKR_GENERAL_ERROR);

	CK_SLOT_ID slots[16];
	CK_ULONG nslots = 16;
	if (fl->C_GetSlotList(CK_TRUE, slots, &nslots) != CKR_OK || nslots == 0)
		ckfail("C_GetSlotList", CKR_GENERAL_ERROR);

	CK_SESSION_HANDLE sess;
	if (fl->C_OpenSession(slots[0],
			CKF_SERIAL_SESSION | CKF_RW_SESSION,
			NULL, NULL, &sess) != CKR_OK)
		ckfail("C_OpenSession", CKR_GENERAL_ERROR);
	if (fl->C_Login(sess, CKU_USER, (CK_BYTE *)"4321", 4) != CKR_OK)
		ckfail("C_Login", CKR_GENERAL_ERROR);

	const char *label = "ed25519-test";
	CK_OBJECT_CLASS cls_priv = CKO_PRIVATE_KEY;
	CK_OBJECT_CLASS cls_pub = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE tpri[] = {
		{ CKA_CLASS, &cls_priv, sizeof cls_priv },
		{ CKA_LABEL, (void *)label, strlen(label) },
	};
	CK_ATTRIBUTE tpub[] = {
		{ CKA_CLASS, &cls_pub, sizeof cls_pub },
		{ CKA_LABEL, (void *)label, strlen(label) },
	};
	CK_OBJECT_HANDLE obj, objs[8];
	CK_ULONG nobj = 0;

	fl->C_FindObjectsInit(sess, tpri, 2);
	if (fl->C_FindObjects(sess, objs, 8, &nobj) != CKR_OK || nobj != 1)
		ckfail("find private key", CKR_GENERAL_ERROR);
	obj = objs[0];
	fl->C_FindObjectsFinal(sess);

	CK_OBJECT_HANDLE pubobj = CK_INVALID_HANDLE;
	fl->C_FindObjectsInit(sess, tpub, 2);
	if (fl->C_FindObjects(sess, objs, 8, &nobj) != CKR_OK || nobj != 1)
		ckfail("find public key", CKR_GENERAL_ERROR);
	pubobj = objs[0];
	fl->C_FindObjectsFinal(sess);

	CK_BYTE ecpoint[128];
	CK_ATTRIBUTE gatt[] = { { CKA_EC_POINT, ecpoint, sizeof ecpoint } };
	if (fl->C_GetAttributeValue(sess, pubobj, gatt, 1) != CKR_OK)
		ckfail("CKA_EC_POINT", CKR_GENERAL_ERROR);
	/* CKA_EC_POINT is DER OCTET STRING: 04 <len> <raw key> */
	if (gatt[0].ulValueLen < 3 || ecpoint[0] != 0x04)
		ckfail("CKA_EC_POINT format", CKR_GENERAL_ERROR);
	const unsigned char *raw = ecpoint + 2;
	const unsigned long rawlen = gatt[0].ulValueLen - 2;
	printf("public key: %lu bytes\n", rawlen);

	/* --- the actual provider test --- */
	EVP_PKEY *pk = pkcs11_provider_key(raw, rawlen, fl, sess, obj);
	if (pk == NULL) {
		fprintf(stderr, "provider key creation FAILED\n");
		ERR_print_errors_fp(stderr);
		return 1;
	}
	printf("provider key created\n");

	/* export path: keymgmt get_params must return the public key */
	unsigned char pubbuf[64];
	size_t pubout = sizeof pubbuf;
	int rr = EVP_PKEY_get_raw_public_key(pk, pubbuf, &pubout);
	if (rr <= 0 || pubout != rawlen || memcmp(pubbuf, raw, rawlen) != 0) {
		fprintf(stderr, "raw public key export FAILED (ret=%d len=%zu)\n",
			rr, pubout);
		ERR_print_errors_fp(stderr);
		return 1;
	}
	printf("raw public key export via provider: OK (%zu bytes)\n", pubout);

	const char *msg = "hello provider";
	EVP_MD_CTX *sctx = EVP_MD_CTX_new();
	size_t siglen = 0;
	if (EVP_DigestSignInit(sctx, NULL, NULL, NULL, pk) <= 0) {
		fprintf(stderr, "DigestSignInit FAILED\n");
		ERR_print_errors_fp(stderr);
		return 1;
	}
	if (EVP_DigestSign(sctx, NULL, &siglen, (const unsigned char *)msg,
				strlen(msg)) <= 0) {
		fprintf(stderr, "DigestSign(size) FAILED\n");
		ERR_print_errors_fp(stderr);
		return 1;
	}
	printf("signature size query: %zu\n", siglen);
	unsigned char sig[64];
	if (EVP_DigestSign(sctx, sig, &siglen, (const unsigned char *)msg,
				strlen(msg)) <= 0) {
		fprintf(stderr, "DigestSign FAILED\n");
		ERR_print_errors_fp(stderr);
		return 1;
	}
	printf("signed via provider (C_Sign): %zu bytes\n", siglen);
	EVP_MD_CTX_free(sctx);

	EVP_PKEY *spk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
						raw, rawlen);
	EVP_MD_CTX *vctx = EVP_MD_CTX_new();
	EVP_DigestVerifyInit(vctx, NULL, NULL, NULL, spk);
	int v = EVP_DigestVerify(vctx, sig, siglen, (const unsigned char *)msg,
				strlen(msg));
	printf("verify with software key: %s\n",
		v == 1 ? "OK" : (v == 0 ? "MISMATCH" : "ERROR"));
	EVP_MD_CTX_free(vctx);

	/* tamper check */
	sig[0] ^= 0xff;
	EVP_DigestVerifyInit(vctx = EVP_MD_CTX_new(), NULL, NULL, NULL, spk);
	v = EVP_DigestVerify(vctx, sig, siglen, (const unsigned char *)msg,
				strlen(msg));
	printf("tampered signature rejected: %s\n", v == 0 ? "OK" : "NO");
	EVP_MD_CTX_free(vctx);
	return v == 0 ? 0 : 1;
#endif
}
