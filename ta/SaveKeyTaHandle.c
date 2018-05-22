/*
 ****************************************************************************************
 *
 *               SaveKeyTaHandle.c
 *
 * Filename      : SaveKeyTaHandle.c
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.com
 * Create Time   : Wed 04 Jan 2017 03:14:17 PM CST
 ****************************************************************************************
 */

#define MOUDLE_OPTEE_SAVE_KEY_HANDLE_C_

/** @defgroup MODULE_NAME_INFOR
* @{
*/

/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "SaveKeyTaHandle.h"
#include "SaveKeyTaAes.h"
#include "SaveKeyTaDebug.h"
#include "SaveKeyTaHash.h"
#include "SaveKeyTaPbkdf2.h"
#include "SaveKeyTaRsa.h"
#include "SaveKeyTaDebug.h"
#include "SaveKeyTaBase64.h"
#include "SaveKeyTaSecStor.h"




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
UINT32 l_SaveKeyTa_Str2short(CHAR* input);
int l_SaveKeyTa_CompareMagicNum(CHAR* strOne, CHAR* strTwo, UINT32 len);
int l_SaveKeyTa_CompareHash(CHAR* input, CHAR* hashValue, UINT32 inputLen);
int l_SaveKeyTa_CalKey(CHAR* plainData);
static void l_SaveKeyTa_GetDecKey(void);
int g_SaveKeyTa_SaveData(uint32_t paramTypes, TEE_Param params[4]);
int g_SaveKeyTa_GetKey(uint32_t paramTypes, TEE_Param params[4]);





/*
 *******************************************************************************
 *                          VARIABLES USED ONLY BY THIS MODULE
 *******************************************************************************
*/
static CHAR g_DecKey[32] = {0};

static CHAR g_MagicNum[4] = {0x12, 0xA8, 0x84, 0x93};
static CHAR g_SavedKey[32] = {0};

/*
 *******************************************************************************
 *                               FUNCTIONS IMPLEMENT
 *******************************************************************************
*/

/** @ingroup MODULE_MANAGE_KEY_TA
 *- #Description  This function for changing the char data into UINT32(big end)
 * @param   input       [IN] Point to the string need to be changed
 *                               - Type: CHAR*
 *                               - Range: N/A.
 *
 * @return     UINT32
 * @retval     l_RetVal: The result after changed
 *
 *
 */
UINT32 l_SaveKeyTa_Str2short(CHAR* input)
{
    UINT32 l_RetVal = 0U;
    l_RetVal = (UINT32)(input[1]);
    l_RetVal += (((UINT32)(input[0])) << 8U);
    
    return l_RetVal;
}



/** @ingroup MODULE_MANAGE_KEY_TA
 *- #Description  This function for comparing the serial number which from CA & ciphertext data
 * @param   strOne           [IN] Point to string one
 *                               - Type: CHAR *
 *                               - Range: N/A.
 * @param   strTwo           [IN] Point to string two
 *                               - Type: CHAR *
 *                               - Range: N/A.
 * @param   len              [IN] The length of string
 *                               - Type: UINT32
 *                               - Range: N/A.
 *
 * @return     int
 * @retval     OK : tow string is same
 * @retval     FAIL : tow string is different
 *
 *
 */
int l_SaveKeyTa_CompareMagicNum(CHAR* strOne, CHAR* strTwo, UINT32 len)
{
    UINT32 l_Index = 0U;
    int l_Ret = OK;

    /**1) Do compare oeration */
    for(l_Index = 0U; l_Index < len; l_Index++)
    {
        if(strOne[l_Index] != strTwo[l_Index])
        {
            l_Ret = FAIL;
        }
    }

    /**2) Return compare result */
    return l_Ret;
}





/** @ingroup MODULE_MANAGE_KEY_TA
 *- #Description  This function for comparing the serial number which from CA & ciphertext data
 * @param   strOne           [IN] Point to string one
 *                               - Type: CHAR *
 *                               - Range: N/A.
 * @param   strTwo           [IN] Point to string two
 *                               - Type: CHAR *
 *                               - Range: N/A.
 * @param   len              [IN] The length of string
 *                               - Type: UINT32
 *                               - Range: N/A.
 *
 * @return     int
 * @retval     OK : tow string is same
 * @retval     FAIL : tow string is different
 *
 *
 */
int l_SaveKeyTa_CompareHash(CHAR* input, CHAR* hashValue, UINT32 inputLen)
{
    UINT32 l_Index = 0U;
    int l_Ret = OK;
    CHAR l_Tmp[32] = {0};
    UINT32 l_hashLen = 32U;

    /**1) Calculate hash value */
    l_Ret = g_SaveKeyTaHash_sha(input, inputLen, l_Tmp, &l_hashLen);
#ifdef DEBUG_ENABLE
    TF("[TA]Input hash is:\n");
    //g_TA_Printf(hashValue, 32U);

    TF("[TA]Calulate hash is:\n");
    //g_TA_Printf(l_Tmp, 32U);
#endif
    l_Ret = OK;

    /**2) Do compare oeration */
    for(l_Index = 0U; l_Index < 32U; l_Index++)
    {
        if(hashValue[l_Index] != l_Tmp[l_Index])
        {
            //TF("[TA]Diff:%d\n", l_Index);
            l_Ret = FAIL;
            break;
        }
    }

    /**3) Return compare result */
    return l_Ret;
}













/** @ingroup MODULE_MANAGE_KEY_TA
 *- #Description  This function for encrypting input data by CPU ID
 * @param   plainData    [IN] Point to the data need be encrypted
 *                               - Type: CHAR*
 *                               - Range: N/A.
 * @param   output       [OUT] Buffer for saving the ciphertext
 *                               - Type: CHAR*
 *                               - Range: N/A.
 *
 * @return     int
 * @retval     OK: Do encrypt operation successful
 * @retval     FAIL: Do encrypt operation fail
 *
 *
 */
int l_SaveKeyTa_CalKey(CHAR* plainData)
{
    int l_RetVal = FAIL;
    CHAR l_SaltData[32] = {0};      /* Salt from input */
    CHAR l_PasswordData[32] = {0};  /* Password from input */
    UINT32 l_SaltLen = 0U;
    UINT32 l_PasswordLen = 0U;
    UINT32 l_Count = 0U;

    /**2) Get Salt & Password data */
    l_Count = (UINT32)(plainData[7]);
    l_SaltLen = (UINT32)(plainData[40]);
    l_PasswordLen = (UINT32)(plainData[73]);
    TEE_MemMove(l_SaltData, &(plainData[8]), l_SaltLen);
    TEE_MemMove(l_PasswordData, &(plainData[41]), l_PasswordLen);

#ifdef DEBUG_ENABLE
    TF("l_SaltData dta:\n");
    g_TA_Printf(l_SaltData, l_SaltLen);
    TF("l_PasswordData dta:\n");
    g_TA_Printf(l_PasswordData, l_PasswordLen);
#endif

    /**3) Do enc operation */
    l_RetVal = g_SaveKeyTaHash_pbkdf2(g_SavedKey, 32U, l_PasswordData, l_PasswordLen, l_SaltData, l_SaltLen, l_Count);

#ifdef DEBUG_ENABLE
        TF("Saved key:\n");
        g_TA_Printf(g_SavedKey, 32U);
#endif
    
    /**4) Return the result */
    return l_RetVal;
}




static void l_SaveKeyTa_GetDecKey(void)
{
    CHAR l_Password[] = "default Password Value!";  /* Password, you can change it or replace it by yourself */
    CHAR l_SaltData[] = "default salt value@";   /* Salt, you can change it or replace it by yourself */
    g_SaveKeyTaHash_pbkdf2(g_DecKey, 32U, l_Password, sizeof(l_Password), l_SaltData, sizeof(l_SaltData), 16);
}

int g_SaveKeyTa_SaveData(uint32_t paramTypes, TEE_Param params[4])
{
    CHAR* l_pMessage = NULL;
    UINT32 l_MessageLen = 0U;
    int l_RetVal = FAIL;
    UINT32 l_plaintextLen = 0U;
    CHAR* l_plaintext = NULL;
    CHAR* l_pBase64 = NULL;
    UINT32 l_Base64Len = 144U;
    CHAR l_TempBufKey[32] = {0};


    
    /**1) Get the request length & point of responding buffer */
    l_MessageLen = params[0].memref.size;
    l_pMessage = params[0].memref.buffer;
    TF("ParamTypes is :%d\n", paramTypes);

    /**2) Get decrypt Key */
    l_SaveKeyTa_GetDecKey();

#ifdef DEBUG_ENABLE
    TF("The Decrypt Key is: %d\n", 32);
    //g_TA_Printf(g_DecKey, 32);
#endif

    /**2) Malloc the buffer for saving base64 decode data */
    l_plaintext = (CHAR*)TEE_Malloc((l_Base64Len - 32U), 0);
    l_pBase64 = (CHAR*)TEE_Malloc(l_Base64Len, 0);

#ifdef DEBUG_ENABLE
    TF("Message of input data is:%d\n", l_MessageLen);
    //g_TA_Printf(l_pMessage, l_MessageLen);
#endif

    /** 2) Decode input meassage */
    g_SaveKeyTaBase64_decode(l_pMessage, l_MessageLen, l_pBase64, l_Base64Len);

    /**4) Verify the input data after do base64 decode operation */
    //l_RetVal = g_SaveKeyTaRsa_rsaVerify(l_pBase64, l_Base64Len);
    //TF("Verify result is:%d\n", l_RetVal);
    l_RetVal = l_SaveKeyTa_CompareHash(l_pBase64, &(l_pBase64[112]), 112);
    if(OK != l_RetVal)
    {
#ifdef DEBUG_ENABLE
        TF("[TA]Compare hash value result:%d\n", l_RetVal);
#endif
    }

    /**6) Calculate AES key & IV */
    if(OK == l_RetVal)
    {
        l_plaintextLen = l_Base64Len - 32U;
        TF("l_plaintextLen: %d\n", l_plaintextLen);
        l_RetVal = g_SaveKeyTa_AesDecData(l_pBase64, l_plaintextLen, l_plaintext, g_DecKey);
#ifdef DEBUG_ENABLE
        TF("[TA]Decrypt output just like follow:\n");
       g_TA_Printf(l_plaintext, l_plaintextLen);
#endif
    }
    else
    {
        goto cleanup_1;
    }

    /** 7) Check hash in data */
    if(OK == l_RetVal)
    {
        l_RetVal = l_SaveKeyTa_CompareHash(l_plaintext, &(l_plaintext[l_plaintextLen - 32U]), l_plaintextLen - 32U);

#ifdef DEBUG_ENABLE
        TF("[TA]Compare hash value result:%d\n", l_RetVal);
#endif
    }
    else
    {
        goto cleanup_2;
    }

    /**7) Compare Magic Number data */
    if(OK == l_RetVal)
    {
        l_RetVal = l_SaveKeyTa_CompareMagicNum(&(l_plaintext[1]), g_MagicNum, 4U);
#ifdef DEBUG_ENABLE
        TF("The compare result is:%d\n", l_RetVal);
#endif
    }
    else
    {
        goto cleanup_2;
    }

    /**8) CalCulate Save Key info */
    if(OK == l_RetVal)
    {
        l_RetVal = l_SaveKeyTa_CalKey(l_plaintext);
    }

    /** 9 Save key by using secure storage */
    g_SecStorTa_CreateFile();
    g_SecStorTa_Write(g_SavedKey, 32);
    g_SecStorTa_Read(l_TempBufKey, 32);
    g_TA_Printf(l_TempBufKey, 32);

cleanup_2:
    TEE_Free(l_plaintext);
cleanup_1:
    return OK;
}


int g_SaveKeyTa_GetKey(uint32_t paramTypes, TEE_Param params[4])
{
    
    CHAR l_TempBufKey[32] = {0};
    int l_Ret = FAIL;
    (void)paramTypes;
    (void)params;
    
    
    l_Ret = g_SecStorTa_Read(l_TempBufKey, 32);
    if(TEE_SUCCESS == l_Ret)
    {
        g_TA_Printf(l_TempBufKey, 32);
        l_Ret = OK;
    }

    return l_Ret;
}































/**
 * @}
 */
