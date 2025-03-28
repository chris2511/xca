# CMake function to find the headerfile x509_vfy.h and search for all occurrences
# of X509_V_ERR_ and replace them by #ifdef x V_ERR(x) #endif

if (OPENSSL_INCLUDE_DIR)
    set(OPENSSL_V_ERR_H "${OPENSSL_INCLUDE_DIR}/openssl/x509_vfy.h")
    if (EXISTS "${OPENSSL_V_ERR_H}")
        message(STATUS "Parsing ${OPENSSL_V_ERR_H} for X509_V_ERR_")
        file(READ "${OPENSSL_V_ERR_H}" X509_VFY_H)
        string(REGEX MATCHALL "X509_V_ERR_[A-Z_0-9]+" X509_VFY_ERRORS ${X509_VFY_H})
        foreach(ERR ${X509_VFY_ERRORS})
            string(APPEND X509_VFY_ERRORS_C "#ifdef ${ERR}\n V_ERR(${ERR})\n#endif\n")
        endforeach()
        file(WRITE ${CMAKE_BINARY_DIR}/openssl_v_err.c ${X509_VFY_ERRORS_C})
    endif()
endif()
