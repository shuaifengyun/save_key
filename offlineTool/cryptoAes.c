/*
 ****************************************************************************************
 *
 *               cryptoAes.c
 *
 * Filename      : cryptoAes.c
 * Programmer(s) : system BSP
 * Filename      : cryptoAes.c
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.com
 * Create Time   : Thu 20 Aug 2015 03:01:41 AM EDT
 ****************************************************************************************
 */

#define MOUDLE_AES_C_

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
#include "cryptoAes.h"



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

static CHAR g_AesKey[16] = {0};

static CHAR g_AesIv[16] = {0};


CHAR g_EncKey[32] = {0};


/*
 *******************************************************************************
 *                               FUNCTIONS IMPLEMENT
 *******************************************************************************
*/

void l_CryptoAes_InitCtr(CtrState* state, CHAR* iv)
{
    state->num = 0;
    memset(state->ecount, 0, 16);
    memset(state->ivec, 0, 16);
    memcpy(state->ivec, iv, 16);
}



void l_CryptoAes_EcbOperation(AES_KEY* aesKey, CHAR* pInput, UINT32 inLen, CHAR* pOutput, int enc)
{
    UINT32 l_loop = 0U;
    UINT32 l_Index = 0U;
    l_loop = inLen / 16U;
    for(l_Index = 0U; l_Index < l_loop; l_Index++)
    {
        AES_ecb_encrypt((pInput + (l_Index * 16U)), (pOutput + (l_Index * 16U)), aesKey, enc);
    }
}

static void l_Crypto_GetEncKey(void)
{
    CHAR l_Password[] = "default Password Value!";  /* Password, you can change it or replace it by yourself */
    CHAR l_SaltData[] = "default salt value@";   /* Salt, you can change it or replace it by yourself */
    g_CryptoPbkdf_PbkdfOperation(l_Password, sizeof(l_Password), l_SaltData, sizeof(l_SaltData), 
        16, 32, g_EncKey);
    printf("g_EncKey is like:\n");
    g_Debug_Printf(g_EncKey, 32);
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
void g_CryptoAes_encrypt(CHAR* pInput, UINT32 inLen, EN_AES_MODE aesMode, CHAR* pOutput)
{
    int l_Result = 0;
    AES_KEY ass_key;
    CtrState l_State;
    
    memset(&ass_key, 0, sizeof(AES_KEY));
    l_Crypto_GetEncKey();
    memcpy(g_AesKey, g_EncKey, 16U);
    memcpy(g_AesIv, &(g_EncKey[16]), 16U);

    l_Result = AES_set_encrypt_key((const char *)g_AesKey, 128, &ass_key);
    if(0 > l_Result)
    {
        printf("ERROR: set encrypt key error!!!\n");
    }
    else
    {

        if(EN_MODE_CTR == aesMode)
        {
            l_CryptoAes_InitCtr(&l_State, g_AesIv);
        }
        
        switch(aesMode)
        {
            case EN_MODE_CBC:
                AES_cbc_encrypt(pInput, pOutput, inLen, &ass_key, g_AesIv, AES_ENCRYPT);
                break;
            case EN_MODE_ECB:
                l_CryptoAes_EcbOperation(&ass_key, pInput, inLen, pOutput, AES_ENCRYPT);
                break; 
            case EN_MODE_CTR:
                AES_ctr128_encrypt(pInput, pOutput, inLen, &ass_key, l_State.ivec, l_State.ecount, &(l_State.num));
                break;
            case EN_MODE_CBC_CTS:
                break;
            default:
                printf("ERROR: input invalid aes mode!!!\n");
                break;  
        }
    }
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
void g_CryptoAes_decrypt(CHAR* pInput, UINT32 inLen, EN_AES_MODE aesMode, CHAR* pOutput)
{
    int l_Result = 0;
    AES_KEY ass_key;
    CtrState l_State;
    
    memset(&ass_key, 0, sizeof(AES_KEY));
    if(EN_MODE_CTR == aesMode)
    {
        l_Result = AES_set_encrypt_key((const char *)g_AesKey, 128, &ass_key);
    }
    else
    {
        l_Result = AES_set_decrypt_key((const char *)g_AesKey, 128, &ass_key);
    }
    
    if(0 > l_Result)
    {
        printf("ERROR: set encrypt key error!!!\n");

    }
    else
    {
        if(EN_MODE_CTR == aesMode)
        {
            l_CryptoAes_InitCtr(&l_State, g_AesIv);
        }

        switch(aesMode)
        {
            case EN_MODE_CBC:
                AES_cbc_encrypt(pInput, pOutput, inLen, &ass_key, g_AesIv, AES_DECRYPT);
                break;
            case EN_MODE_ECB:
                l_CryptoAes_EcbOperation(&ass_key, pInput, inLen, pOutput, AES_DECRYPT);
                break; 
            case EN_MODE_CTR:
                AES_ctr128_encrypt(pInput, pOutput, inLen, &ass_key, l_State.ivec, l_State.ecount, &(l_State.num));
                break;
            case EN_MODE_CBC_CTS:
                break;
            default:
                printf("ERROR: input invalid aes mode!!!\n");
                break;  
        }
    }
}
















/**
 * @}
 */
