
/*
 ****************************************************************************************
 *
 *               SaveKeyTaAes.c
 *
 * Filename      : SaveKeyTaAes.c
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.com
 * Create Time   : Wed 04 Jan 2017 03:11:59 PM CST
 ****************************************************************************************
 */

#define MOUDLE_OPTEE_SAVE_KEY_AES_C_

/** @defgroup MODULE_NAME_INFOR
* @{
*/

/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "SaveKeyTaAes.h"
#include "SaveKeyTaPbkdf2.h"
#include "SaveKeyTaDebug.h"





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
    CHAR g_Aes128Key[] = {0x2FU, 0x58U, 0x7FU, 0xF0U, 0x43U, 0x83U, 0x95U, 0x3CU,
                          0x1DU, 0x44U, 0x05U, 0x2BU, 0x61U, 0x49U, 0x17U, 0xF8U};
    CHAR g_Aes128Iv[] = {0x1DU, 0x44U, 0x05U, 0x2BU, 0x61U, 0x49U, 0x17U, 0xF8U,
                         0x58U, 0xE0U, 0x90U, 0x43U, 0x84U, 0xA1U, 0xC1U, 0x75U};





/*
 *******************************************************************************
 *                          FUNCTIONS USED ONLY BY THIS MODULE
 *******************************************************************************
*/
int g_SaveKeyTa_AesDecData(CHAR* cipherText, UINT32 cipherLen, CHAR* plainText, CHAR* key);
static void l_CryptoTaHandle_SetAesAction(AesOperation* aesOper, AesOperModeInfo modeInfo);
int l_CryptoTaAes_AesOper(AesOperation aesOper);





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
/** @ingroup MODULE_MANAGE_KEY_TA
 *- #Description  This function for decrypting input data with AES Algorithm
 * @param   cipherText       [IN] Point to the ciphertext, need be decrypted
 *                               - Type: SaveDeviceIdContext *
 *                               - Range: N/A.
 * @param   cipherLen        [IN] Length of ciphertext data
 *                               - Type: UINT32
 *                               - Range: N/A.
 * @param   plainText        [OUT] Buffer for saving output after decrypt
 *                               - Type: CHAR*
 *                               - Range: N/A.
 * @param   sn               [IN] Point to the serial number 
 *                               - Type: CHAR*
 *                               - Range: N/A.
 * @param   snLen            [IN] The length of serial number data
 *                               - Type: UINT32
 *                               - Range: N/A.
 * @param   encType          [IN] The select of AES algorithm(AES128 or AES256)
 *                               - Type: UINT32
 *                               - Range: N/A.
 *
 * @return     int
 * @retval     OK: Do decrypt operation successful
 * @retval     FAIL: Do decrypt operation fail
 *
 *
 */



static void l_CryptoTaHandle_SetAesAction(AesOperation* aesOper, AesOperModeInfo modeInfo)
{
    switch(modeInfo.active)
    {
        case EN_OP_AES_ENCRYPT:
            aesOper->operMode = TEE_MODE_ENCRYPT;
            break;
        case EN_OP_AES_DECRYPT:
            aesOper->operMode = TEE_MODE_DECRYPT;
            break;
        default:
            break;
    }

    switch(modeInfo.mode)
    {
        case EN_MODE_CBC:
            aesOper->algorithmId= TEE_ALG_AES_CBC_NOPAD;
            break;
        case EN_MODE_ECB:
            aesOper->algorithmId = TEE_ALG_AES_ECB_NOPAD;
            break;
        case EN_MODE_CTR:
            aesOper->algorithmId = TEE_ALG_AES_CTR;
            break;
        case EN_MODE_CBC_CTS:
            aesOper->algorithmId = TEE_ALG_AES_CTS;
            break;
        default:
            break;
    }
}



int l_CryptoTaAes_AesOper(AesOperation aesOper)
{
    TEE_OperationHandle l_pOperation = NULL;
    TEE_ObjectHandle l_pKeyObj = NULL;
    TEE_Attribute l_pAttr;
    CHAR* l_pInbuf = aesOper.inBuf;
    CHAR* l_pOutbuf = aesOper.outBuf;
    UINT32 l_dataLen = aesOper.dataLen;
    TEE_Result l_RetVal = TEE_FAIL;
    int l_Result = FAIL;
 
    TF("The Aes operation information just like follow:\n");
    TF("Aes key=\n");
    g_TA_Printf(aesOper.key, aesOper.keyLen);
    TF("IV=\n");
    g_TA_Printf(aesOper.iv, aesOper.ivLen);
    TF("Algorith= 0x%x\n", aesOper.algorithmId);
    TF("Mode=0x%x\n", aesOper.operMode);
    TF("Raw just like follow:%d\n", aesOper.dataLen);
    g_TA_Printf(aesOper.inBuf, aesOper.dataLen);

    /**1) Allocate the operation handle */
    l_RetVal = TEE_AllocateOperation(&l_pOperation, aesOper.algorithmId, aesOper.operMode, aesOper.keyLen);
    if(TEE_SUCCESS != l_RetVal)
    {
        l_Result = FAIL;
        goto cleanup_1;
    }

    TF("Allocate object\n");
    /**2) Allocate the object handle */
    l_RetVal = TEE_AllocateTransientObject(TEE_TYPE_AES, aesOper.keyLen, &l_pKeyObj);
    if(TEE_SUCCESS != l_RetVal)
    {
        l_Result = FAIL;
        goto cleanup_1;
    }   

    TF("Init attribute\n");
    /**3) Set the key object parameter */
    TEE_InitRefAttribute(&l_pAttr, TEE_ATTR_SECRET_VALUE, aesOper.key, 16);
    l_RetVal = TEE_PopulateTransientObject(l_pKeyObj, &l_pAttr, 1);
    if(TEE_SUCCESS != l_RetVal)
    {
        l_Result = FAIL;
        goto cleanup_1;
    }

    TF("Set key\n");
    /**4) Assemble aes operation handle */
    l_RetVal = TEE_SetOperationKey(l_pOperation, l_pKeyObj);
    if(TEE_SUCCESS != l_RetVal)
    {
        l_Result = FAIL;
        goto cleanup_2;
    }

    TF("Init cipher\n");
    /**5) Initialze cipher operation */
    TEE_CipherInit(l_pOperation, aesOper.iv, aesOper.ivLen);


#if 0
    /**6) Update the input data into the buffer for do AES operation */
    while(true)
    {
        if(SIZE_OF_AES128_BLOCK_LEN == l_dataLen)
        {
            break;
        }
        else
        {
            if(0U != (l_dataLen / SIZE_OF_AES128_BLOCK_LEN))
            {
                /* Do update operation */
                l_RetVal = TEE_CipherUpdate(l_pOperation, l_pInbuf, SIZE_OF_AES128_BLOCK_LEN,
                                              l_pOutbuf, SIZE_OF_AES128_BLOCK_LEN);
                if(TEE_SUCCESS != l_RetVal)
                {
                    l_Result = FAIL;
                    goto cleanup_2;
                }

                /* Move the buffer point & length of remainder data */
                l_pInbuf = &(l_pInbuf[SIZE_OF_AES128_BLOCK_LEN]);
                l_pOutbuf = &(l_pOutbuf[SIZE_OF_AES128_BLOCK_LEN]);
                l_dataLen = l_dataLen - SIZE_OF_AES128_BLOCK_LEN;
            }
            else
            {
                break;
            }
            
        }
    }
#endif

    TF("Do final cipher\n");
    /** 6) Do the final AES operation */
    l_RetVal = TEE_CipherDoFinal(l_pOperation, l_pInbuf, l_dataLen, l_pOutbuf, &l_dataLen);
   
    if(TEE_SUCCESS != l_RetVal)
    {
        l_Result = FAIL;
    }
    else
    {
        l_Result = OK;
    }

    TF("The aes operation out put just like follow:\n");
    //g_TA_Printf(aesOper.outBuf, aesOper.dataLen);



cleanup_2:
    TEE_FreeOperation(l_pOperation);
cleanup_1:
    return l_Result;
}





int g_SaveKeyTa_AesDecData(CHAR* cipherText, UINT32 cipherLen, CHAR* plainText, CHAR* key)
{
    int l_Ret = FAIL;
    AesOperation l_aesOper;
    AesOperModeInfo l_pAesModeInfo;
    l_pAesModeInfo.active = EN_OP_AES_DECRYPT;
    l_pAesModeInfo.mode = EN_MODE_CBC;
    l_aesOper.inBuf = cipherText;
    l_aesOper.outBuf = plainText;
    l_aesOper.dataLen = cipherLen;
    l_aesOper.key = key;
    l_aesOper.iv = &(key[16]);
    l_aesOper.keyLen = 128U;
    l_aesOper.ivLen = 16U;

    TF("Data len is: %d\n", l_aesOper.dataLen);

    l_CryptoTaHandle_SetAesAction(&l_aesOper, l_pAesModeInfo);
    
    /**4) Do AES operation */
    l_Ret = l_CryptoTaAes_AesOper(l_aesOper);

    /**3) Return operation result */
    return l_Ret;
}












/**
 * @}
 */
