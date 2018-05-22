/*
 ****************************************************************************************
 *
 *               SaveKeyTaHash.c
 *
 * Filename      : SaveKeyTaHash.c
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.com
 * Create Time   : Wed 04 Jan 2017 03:14:26 PM CST
 ****************************************************************************************
 */

#define MOUDLE_OPTEE_SAVE_KEY_HASH_C_

/** @defgroup MODULE_NAME_INFOR
* @{
*/

/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "SaveKeyTaHash.h"
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





/*
 *******************************************************************************
 *                          FUNCTIONS USED ONLY BY THIS MODULE
 *******************************************************************************
*/
int g_SaveKeyTaHash_sha(CHAR* input, UINT32 inLen, CHAR* output, UINT32* pOutLen);





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
int g_SaveKeyTaHash_sha(CHAR* input, UINT32 inLen, CHAR* output, UINT32* pOutLen)
{
    TEE_Result ret;
    TEE_OperationHandle l_OperationHandle;   
    int l_RetVal = OK;
    
    #ifdef DEBUG_ENABLE
    TF("Input data just like follow(0x%x), 0x%x:\n", inLen, (UINT32)(output));
    //g_TA_Printf(input, inLen);
    #endif

    /**2) Allocate the operation handle */
    ret = TEE_AllocateOperation(&l_OperationHandle, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if(ret != TEE_SUCCESS) 
    {
        #ifdef DEBUG_ENABLE
        TF("Allocate SHA operation handle fail\n");
        #endif
        l_RetVal = FAIL;
        goto cleanup_1;
    }

    TEE_DigestUpdate(l_OperationHandle, input, inLen);

    /**4) Do the final sha operation */
    ret = TEE_DigestDoFinal(l_OperationHandle, NULL, 0, output, pOutLen);
#ifdef DEBUG_ENABLE
    TF("The out put length is :%d\n", *pOutLen);
    TF("The return value is :0x%x\n", ret);
#endif
    if(ret != TEE_SUCCESS)
    {
    #ifdef DEBUG_ENABLE
        TF("Do the final sha operation fail\n");
    #endif
        l_RetVal = FAIL;
        goto cleanup_2;
    }
    
#ifdef DEBUG_ENABLE
    TF("Hash value just like folloe:\n");
    g_TA_Printf(output, *pOutLen);
#endif

    /**5) Do the clean up operation& return the result */
    cleanup_2:
        TEE_FreeOperation(l_OperationHandle);
    cleanup_1:
        return l_RetVal;
}





















/**
 * @}
 */
