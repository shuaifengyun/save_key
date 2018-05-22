/*
 ****************************************************************************************
 *
 *               cryptoRsa.c
 *
 * Filename      : cryptoRsa.c
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.com
 * Create Time   : Thu 20 Aug 2015 03:01:51 AM EDT
 ****************************************************************************************
 */

#define MOUDLE_RSA_C_

/** @defgroup MODULE_NAME_INFOR
* @{
*/

/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "cryptoType.h"
#include "cryptoDebug.h"





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





/*
 *******************************************************************************
 *                               FUNCTIONS IMPLEMENT
 *******************************************************************************
*/
/** @ingroup MOUDLE_NAME_C_
 *- #Description  This function for doing RSA encrypt
 * @param   pMsg           [IN] The received request message
 *                               - Type: MBX_Msg *
 *                               - Range: N/A.
 *
 * @return     void
 * @retval     void
 *
 *
 */
int g_CryptoRsa_Encrypt(CHAR* pubKeyFile, CHAR* inputBuf, UINT32 inLen, CHAR* outputBuf, int padType)
{
    FILE* l_PubFp = NULL;
    RSA* l_RsaPubText = NULL;
    int l_Ret = -1;


    /**1) Open public key file */
    l_PubFp = fopen(pubKeyFile, "r");
    if(NULL == l_PubFp)
    {
        printf("ERROR: Open public key file fail!!\n");
        return -1;
    }

    /**2) Read public key text form key file */
    l_RsaPubText = PEM_read_RSA_PUBKEY(l_PubFp, NULL, NULL, NULL);
    if(NULL == l_RsaPubText)
    {
        printf("ERROR: read public key from file faile!\n");
        return -1;
    }


    printf("Public key:\n");
    printf("n=%s\n", BN_bn2hex(l_RsaPubText->n));
    printf("e=%s\n", BN_bn2hex(l_RsaPubText->e));
    printf("Input Data Length is: %d\n", inLen);
    printf("Input data just like follow:\n");
    printf("%s\n", inputBuf);
    printf("\n\n");

    /**4) RSA Encrypt Input data */
    l_Ret = RSA_public_encrypt(inLen, inputBuf, outputBuf, l_RsaPubText, padType);
    if(-1 == l_Ret)
    {
        printf("ERROR: encrypt input data faile!\n");
        return -1;
    }

    return l_Ret;
}


/** @ingroup MOUDLE_NAME_C_
 *- #Description  This function for doing RSA encrypt
 * @param   pMsg           [IN] The received request message
 *                               - Type: MBX_Msg *
 *                               - Range: N/A.
 *
 * @return     void
 * @retval     void
 *
 *
 */
int g_CryptoRsa_Decrypt(CHAR* priKeyFile, CHAR* inputBuf, UINT32 inLen, CHAR* outputBuf, int padType)
{
    FILE* l_PriFp = NULL;
    RSA* l_RsaPriText = NULL;
    int l_Ret = -1;


    /**1) Open public key file */
    l_PriFp = fopen(priKeyFile, "r");
    if(NULL == l_PriFp)
    {
        printf("ERROR: Open public key file fail!!\n");
        return -1;
    }

    /**2) Read public key text form key file */
    l_RsaPriText = PEM_read_RSAPrivateKey(l_PriFp, NULL, NULL, NULL);
    if(NULL == l_RsaPriText)
    {
        printf("ERROR: read public key from file faile!\n");
        return -1;
    }


    printf("Public key:\n");
    printf("n=%s\n", BN_bn2hex(l_RsaPriText->n));
    printf("e=%s\n", BN_bn2hex(l_RsaPriText->d));

    /**4) RSA Encrypt Input data */
    l_Ret = RSA_private_decrypt(inLen, inputBuf, outputBuf, l_RsaPriText, padType);
    if(-1 == l_Ret)
    {
        printf("ERROR: encrypt input data faile!\n");
        return -1;
    }

    return l_Ret;
    
}







/** @ingroup MOUDLE_NAME_C_
 *- #Description  This function for doing RSA encrypt
 * @param   pMsg           [IN] The received request message
 *                               - Type: MBX_Msg *
 *                               - Range: N/A.
 *
 * @return     void
 * @retval     void
 *
 *
 */
int g_CryptoRsa_Sign(CHAR* priKeyFile, CHAR* inputBuf, UINT32 inLen, CHAR* outputBuf, int padType)
{
    FILE* l_PriFp = NULL;
    RSA* l_RsaPriText = NULL;
    int l_Ret = -1;


    /**1) Open public key file */
    l_PriFp = fopen(priKeyFile, "r");
    if(NULL == l_PriFp)
    {
        printf("ERROR: Open private key file fail!!\n");
        return -1;
    }

    /**2) Read public key text form key file */
    l_RsaPriText = PEM_read_RSAPrivateKey(l_PriFp, NULL, NULL, NULL);
    if(NULL == l_RsaPriText)
    {
        ERR_print_errors_fp(stdout);
        printf("ERROR: read private key from file faile!\n");
        return -1;
    }
    else
    {
        printf("\nPrivate key:\n");
        printf("n=%s\n", BN_bn2hex(l_RsaPriText->n));
        printf("d=%s\n\n", BN_bn2hex(l_RsaPriText->d));
    }
    printf("Input Data Length is: %d\n", inLen);
    printf("Input data just like follow:\n");
    g_Debug_Printf(inputBuf, inLen);

    
    /**4) RSA Encrypt Input data */
    l_Ret = RSA_private_encrypt(inLen, inputBuf, outputBuf, l_RsaPriText, padType);
    printf("%d\n", l_Ret);
 
    if(-1 == l_Ret)
    {
        printf("ERROR: Signature input data faile!\n");
        return -1;
    }

    return l_Ret;
}









/** @ingroup MOUDLE_NAME_C_
 *- #Description  This function for doing RSA encrypt
 * @param   pMsg           [IN] The received request message
 *                               - Type: MBX_Msg *
 *                               - Range: N/A.
 *
 * @return     void
 * @retval     void
 *
 *
 */
int g_CryptoRsa_Verify(CHAR* pubKeyFile, CHAR* RawBuf, UINT32 rawLen, CHAR* signBuf, int padType)
{
    FILE* l_PubFp = NULL;
    RSA* l_RsaPubText = NULL;
    CHAR l_Tmp[256] = {0};
    int l_Ret = -1;


    /**1) Open public key file */
    l_PubFp = fopen(pubKeyFile, "r");
    if(NULL == l_PubFp)
    {
        printf("ERROR: Open public key file fail!!\n");
        return -1;
    }

    /**2) Read public key text form key file */
    l_RsaPubText = PEM_read_RSA_PUBKEY(l_PubFp, NULL, NULL, NULL);
    if(NULL == l_RsaPubText)
    {
        printf("ERROR: read public key from file faile!\n");
        return -1;
    }


    printf("Public key:\n");
    printf("n=%s\n", BN_bn2hex(l_RsaPubText->n));
    printf("e=%s\n", BN_bn2hex(l_RsaPubText->e));

    /**4) RSA Encrypt Input data */
    l_Ret = RSA_public_decrypt(RSA_size(l_RsaPubText), signBuf, l_Tmp, l_RsaPubText, padType);
    printf("The return value is %d\n", l_Ret);
    g_Debug_Printf(l_Tmp, 256);

    l_Ret = RSA_verify(NID_sha1, RawBuf, 20, signBuf, 256, l_RsaPubText);
    printf("The return value is: %d\n", l_Ret);
    if(-1 == l_Ret)
    {
        printf("ERROR: Call openssl verify function fail\n");
        return -1;
    }
    
    /**5) Compare the result */
    l_Ret = memcmp(RawBuf, l_Tmp, rawLen);
    if(0 != l_Ret)
    {
        printf("Verify signature information faile!!!\n");
        return -1;
    }
    else
    {
        printf("Verify signature information ok!!!\n");
    }

    return l_Ret;
}





















/**
 * @}
 */
