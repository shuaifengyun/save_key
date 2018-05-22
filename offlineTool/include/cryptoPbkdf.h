/*
 ****************************************************************************************
 *
 *               cryptoPbkdf.h
 *
 * Filename      : cryptoPbkdf.h
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.com
 * Create Time   : Fri 21 Aug 2015 07:02:21 AM EDT
 ****************************************************************************************
 */

#ifndef MOUDLE_PBKDF_H_
#define MOUDLE_PBKDF_H_




/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "cryptoType.h"




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


#ifndef MOUDLE_PBKDF_C_


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
extern void g_CryptoPbkdf_PbkdfOperation(CHAR* pwd,int pLen, CHAR* salt, int sLen, int count,int dkLen, CHAR* output);
extern void g_CryptoRandom_GenRandomString(CHAR* buf, UINT32 length);
extern void g_Test_hmac(int len);
extern UINT32 g_CryptoBase64_enc(const char *encoded, int encodedLength, char *decoded);
extern UINT32 g_CryptoBase64_dec(unsigned char *input, int length, char* output);















#endif

#endif  /* MOUDLE_NAME_H*/
