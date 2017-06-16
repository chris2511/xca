/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2017 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

/* This header equalizes a lot of OpenSSL 1.1.0 vs. 1.0.0
   API clashes by defining some macros if OpenSSL < 1.1.0
   is used. This way the code is written with the new API
   and have much less #ifdefs
*/

#ifndef __OPENSS_COMPAT_XCA_H
#define __OPENSS_COMPAT_XCA_H

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#define RAND_bytes(buf, size) RAND_pseudo_bytes((buf), (size))
#define X509_get0_extensions(cert) ((cert)->cert_info->extensions)
#define X509_get_signature_nid(cert) OBJ_obj2nid((cert)->sig_alg->algorithm)
#define X509_REQ_get_signature_nid(req) OBJ_obj2nid((req)->sig_alg->algorithm)

#endif

#endif
