/*
 ****************************************************************************************
 *
 *               cryptoType.h
 *
 * Filename      : cryptoType.h
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.com
 * Create Time   : Thu 20 Aug 2015 03:31:51 AM EDT
 ****************************************************************************************
 */

#ifndef MOUDLE_TYPE_H_
#define MOUDLE_TYPE_H_




/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "stdlib.h"
#include "sys/stat.h"
#include "fcntl.h"
#include "dirent.h"
#include "openssl/aes.h"
#include "openssl/crypto.h"
#include "openssl/ssl.h"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include <openssl/pem.h>





/*
 *******************************************************************************
 *                  MACRO DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/





/*
 *******************************************************************************
 *                STRUCTRUE DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/
typedef unsigned char UINT8;    /**< Typedef for 8bits unsigned integer */
typedef unsigned int UINT32;    /**< Typedef for 32bits unsigned integer */
typedef char CHAR;              /**< Typedef for char */

typedef struct SaveKeyPlain_t
{
    CHAR mKeyType;
    CHAR mMagicNum[4];
    CHAR mDataLen[2];
    CHAR mCount;
    CHAR mSaltData[32];
    CHAR mLenSalt;
    CHAR mPasswordData[32];
    CHAR mLenPassword;
    CHAR mResvert[6];
    CHAR mHash[32];
}SaveKeyPlain;

/*
 *******************************************************************************
 *                      VARIABLES SUPPLIED BY THIS MODULE
 *******************************************************************************
*/





/*
 *******************************************************************************
 *                      FUNCTIONS SUPPLIED BY THIS MODULE
 *******************************************************************************
*/





















#endif  /* MOUDLE_NAME_H*/
