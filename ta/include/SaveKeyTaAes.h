/*
 ****************************************************************************************
 *
 *               SaveKeyTaAes.h
 *
 * Filename      : SaveKeyTaAes.h
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.com
 * Create Time   : Wed 04 Jan 2017 03:15:02 PM CST
 ****************************************************************************************
 */

#ifndef MOUDLE_OPTEE_SAVE_KEY_AES_H_
#define MOUDLE_OPTEE_SAVE_KEY_AES_H_




/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "SaveKeyTaType.h"
#include "SaveKeyTaDebug.h"





/*
 *******************************************************************************
 *                  MACRO DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/

#define AES_CBC_ENC      TEE_MODE_ENCRYPT
#define AES_CBC_DEC      TEE_MODE_DECRYPT



/*
 *******************************************************************************
 *                STRUCTRUE DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/
typedef struct _AesOperation
{
    CHAR* inBuf;
    CHAR* outBuf;
    CHAR* key;
    CHAR* iv;
    UINT32 dataLen;
    UINT32 keyLen;
    UINT32 ivLen;
    UINT32 algorithmId;
    TEE_OperationMode operMode;
}AesOperation;



/* AES operation type */
typedef enum
{
    EN_OP_AES_ENCRYPT = 1,
    EN_OP_AES_DECRYPT,
    EN_OP_AES_INVALID
}EN_AES_OPERATION_ACTION;


/* AES mode type */
typedef enum
{
    EN_MODE_CBC = 1,
    EN_MODE_ECB,
    EN_MODE_CTR,
    EN_MODE_CBC_CTS,
    EN_MODE_INVALIE
}EN_AES_MODE;



typedef struct _AesOperModeInfo
{
    EN_AES_OPERATION_ACTION active;
    EN_AES_MODE mode;
}AesOperModeInfo;




#ifndef MOUDLE_OPTEE_SAVE_KEY_AES_C_


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


extern int g_SaveKeyTa_AesDecData(CHAR* cipherText, UINT32 cipherLen, CHAR* plainText, CHAR* key);
















#endif

#endif  /* MOUDLE_NAME_H*/
