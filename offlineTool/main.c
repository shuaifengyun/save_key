/*
 ****************************************************************************************
 *
 *                 main.c
 *
 * Filename      : main.c
 * Filename      : main.c
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.com
 ****************************************************************************************
 */

#define MOUDLE_NAME_C_

/** @defgroup MODULE_NAME_INFOR
* @{
*/

/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "cryptoAes.h"
#include "cryptoDebug.h"
#include "cryptoPbkdf.h"
#include "cryptoRsa.h"
#include "cryptoSha.h"
#include "cryptoType.h"




/*
 *******************************************************************************
 *                         FUNCTIONS SUPPLIED BY THIS MODULE
 *******************************************************************************
*/





/*
 *******************************************************************************
 *                          VARIABLES SUPPLIED BY THIS MODULE
 *******************************************************************************
*/





/*
 *******************************************************************************
 *                          FUNCTIONS USED ONLY BY THIS MODULE
 *******************************************************************************
*/





/*
 *******************************************************************************
 *                          VARIABLES USED ONLY BY THIS MODULE
 *******************************************************************************
*/
SaveKeyPlain g_SaveKeyPlain;        /* Buffer for saving plain data */
CHAR g_MagicNum[4] = {0x12, 0xA8, 0x84, 0x93};      /* Magic number of data */
CHAR g_SaltData[] = "Demo Salt Data for test@@!";   /* Salt data for generating decrypted key */
CHAR g_PwData[] = "Demo password Data for test@@!"; /* Password for generating decrypted key */
CHAR g_Count = 0x0F;        /* Count value for generating decrypted key */
CHAR g_KeyType = 0x81;      /* Key type */
CHAR g_DataLen = 0x4A;      /* Variable length of data */



/*
 *******************************************************************************
 *                               FUNCTIONS IMPLEMENT
 *******************************************************************************
*/
/* Function for packaging plain data */
void l_Crypto_PackagePlainData(void)
{
    /** 1) Clean buffer */
    memset(&g_SaveKeyPlain, 0, sizeof(SaveKeyPlain));

    /** 2) Package data */
    g_SaveKeyPlain.mKeyType = g_KeyType;
    memcpy(g_SaveKeyPlain.mMagicNum, g_MagicNum, 4U);
    g_SaveKeyPlain.mDataLen[0] = 0x00;
    g_SaveKeyPlain.mDataLen[1] = g_DataLen;
    g_SaveKeyPlain.mCount = g_Count;
    memcpy(g_SaveKeyPlain.mSaltData, g_SaltData, sizeof(g_SaltData));
    g_SaveKeyPlain.mLenSalt = (CHAR)(sizeof(g_SaltData));
    memcpy(g_SaveKeyPlain.mPasswordData, g_PwData, sizeof(g_PwData));
    g_SaveKeyPlain.mLenPassword = (CHAR)(sizeof(g_PwData));
}





/** @ingroup MOUDLE_NAME_C_
 *- #Description  This function for handle command.
 * @param   pMsg           [IN] The received request message
 *                               - Type: MBX_Msg *
 *                               - Range: N/A.
 *
 * @return     void
 * @retval     void
 *
 *
 */
int main(int argc, char *argv[])
{
    CHAR l_HashBuf[32] = {0};
    CHAR l_Sha256Buf[32] = {0};
    CHAR* l_pTempBuf =NULL;
    CHAR l_Signature[256] = {0};
    CHAR l_PackageData[362] = {0};
    CHAR* l_pBase64Enc =NULL;
    UINT32 l_Base64Len = 0U;
    CHAR l_Buf[32] = {0};

    /** 1) Package plain data */
    memset(&g_SaveKeyPlain, 0, 112);
    l_Crypto_PackagePlainData();
    printf("PackageData:\n");
    g_Debug_Printf(&g_SaveKeyPlain, 80);


    /** 2) Calculate hash256 */
    g_CryptoSha_shaOper(EN_OP_SHA256, &g_SaveKeyPlain, (sizeof(SaveKeyPlain) - 32U), l_HashBuf);
    memcpy(g_SaveKeyPlain.mHash, l_HashBuf, 32);
    printf("Hash of plain data:\n");
    g_Debug_Printf(l_HashBuf, 32);
    g_Debug_Printf(g_SaveKeyPlain.mHash, 32);

    /** 3) Encrypt plain data */
    l_pTempBuf = malloc(sizeof(SaveKeyPlain));
    g_CryptoAes_encrypt(&g_SaveKeyPlain, sizeof(SaveKeyPlain), EN_MODE_CBC, l_pTempBuf);
    printf("Encrypt Data:\n");
    g_Debug_Printf(&g_SaveKeyPlain, 112);

    /** 4) Signature encrypted data */
    g_CryptoSha_shaOper(EN_OP_SHA256, l_pTempBuf, sizeof(SaveKeyPlain), l_Sha256Buf);

    /** 5) Package data */
    memcpy(l_PackageData, l_pTempBuf, sizeof(SaveKeyPlain));
    memcpy(&(l_PackageData[112]), l_Sha256Buf, 32);

    /** 6) Encode data by using base64 */
    l_pBase64Enc = malloc(362);
    l_Base64Len = g_CryptoBase64_enc(l_PackageData, 144, l_pBase64Enc);
    printf("base64 encoded: %d\n", l_Base64Len);
    printf("%s\n", l_pBase64Enc);

    /** 7) Print out key which send to device */
    printf("\nSaved key is :\n");
    g_CryptoPbkdf_PbkdfOperation(g_SaveKeyPlain.mPasswordData, g_SaveKeyPlain.mLenPassword, 
        g_SaveKeyPlain.mSaltData, g_SaveKeyPlain.mLenSalt, g_SaveKeyPlain.mCount, 32, l_Buf);
    g_Debug_Printf(l_Buf, 32);


    
    return 0;
}




















/**
 * @}
 */
