/*
 ****************************************************************************************
 *
 *               SaveKeyTaPbkdf2.c
 *
 * Filename      : SaveKeyTaPbkdf2.c
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.com
 * Create Time   : Wed 04 Jan 2017 03:14:39 PM CST
 ****************************************************************************************
 */

#define MOUDLE_OPTEE_SAVE_KEY_PBKDF2_C_

/** @defgroup MODULE_NAME_INFOR
* @{
*/

/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
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





/*
 *******************************************************************************
 *                          FUNCTIONS USED ONLY BY THIS MODULE
 *******************************************************************************
*/
int g_SaveKeyTaHash_pbkdf2(CHAR* output, UINT32 OutLen, CHAR* passWd, UINT32 passLen, CHAR* salt, UINT32 saltLen, UINT32 count);





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
int g_SaveKeyTaHash_pbkdf2(CHAR* output, UINT32 OutLen, CHAR* passWd, UINT32 passLen, CHAR* salt, UINT32 saltLen, UINT32 count)
{
    TEE_Result ret;
    int l_RetVal = OK;
    TEE_OperationHandle l_OperationHandle;
    TEE_ObjectHandle l_SvHandle;
    TEE_ObjectHandle l_PassWdObjHandle;
    TEE_Attribute l_Attr;
    TEE_Attribute l_Param[3] = {0};

#ifdef DEBUG_ENABLE
    TF("Pwd:%s\n", passWd);
    TF("Pwd len:%d\n", passLen);
    TF("Salt:%s\n", salt);
    TF("Salt len:%d\n", saltLen);
    TF("dkLen:%d\n", OutLen);
    TF("C:%d\n", count);
#endif

    /**2) Allocate the operation handle */
    ret = TEE_AllocateOperation(&l_OperationHandle, TEE_ALG_PBKDF2_HMAC_SHA1_DERIVE_KEY, TEE_MODE_DERIVE, 2048);
    if(ret != TEE_SUCCESS) 
    {
        l_RetVal = FAIL;
        goto cleanup_1;
    }

    /**4) Do the final sha operation */
    ret = TEE_AllocateTransientObject(TEE_TYPE_PBKDF2_PASSWORD, 2048, &l_PassWdObjHandle);
    if(ret != TEE_SUCCESS)
    {
    #ifdef DEBUG_ENABLE
        TF("Do the final hmac operation fail\n");
    #endif
        l_RetVal = FAIL;
        goto cleanup_2;
    }

    l_Attr.attributeID = TEE_ATTR_PBKDF2_PASSWORD;
    l_Attr.content.ref.buffer = passWd;
    l_Attr.content.ref.length = passLen;
    
    /**4) Do the final sha operation */
    ret = TEE_PopulateTransientObject(l_PassWdObjHandle, &l_Attr, 1);
    if(ret != TEE_SUCCESS)
    {
    #ifdef DEBUG_ENABLE
        TF("Do the final hmac operation fail\n");
    #endif
        l_RetVal = FAIL;
        goto cleanup_2;
    }

    ret = TEE_SetOperationKey(l_OperationHandle, l_PassWdObjHandle);
    if(ret != TEE_SUCCESS)
    {
    #ifdef DEBUG_ENABLE
        TF("Do the final hmac operation fail\n");
    #endif
        l_RetVal = FAIL;
        goto cleanup_2;
    }
    
    /**4) Do the final sha operation */
    ret = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET, OutLen*8, &l_SvHandle);
    if(ret != TEE_SUCCESS)
    {
    #ifdef DEBUG_ENABLE
        TF("Do the final hmac operation fail\n");
    #endif
        l_RetVal = FAIL;
        goto cleanup_2;
    }

    l_Param[0].attributeID = TEE_ATTR_PBKDF2_SALT;
    l_Param[0].content.ref.buffer = salt;
    l_Param[0].content.ref.length = saltLen;

    l_Param[1].attributeID = TEE_ATTR_PBKDF2_DKM_LENGTH;
    l_Param[1].content.value.a = OutLen;
    l_Param[1].content.value.b = 0;
    
    l_Param[2].attributeID = TEE_ATTR_PBKDF2_ITERATION_COUNT;
    l_Param[2].content.value.a = count;
    l_Param[2].content.value.b = 0;

    TEE_DeriveKey(l_OperationHandle, l_Param, 3, l_SvHandle);

    ret = TEE_GetObjectBufferAttribute(l_SvHandle, TEE_ATTR_SECRET_VALUE, output, &OutLen);
    if(ret != TEE_SUCCESS)
    {
    #ifdef DEBUG_ENABLE
        TF("Do the final hmac operation fail\n");
    #endif
        l_RetVal = FAIL;
        goto cleanup_2;
    }

#ifdef DEBUG_ENABLE
    //TF("Hash value just like folloe:\n");
    //g_TA_Printf(output, OutLen);
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
