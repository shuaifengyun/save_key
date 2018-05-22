/*
 ****************************************************************************************
 *
 *               SaveKeyTaEntry.c
 *
 * Filename      : SaveKeyTaEntry.c
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.com
 * Create Time   : Wed 04 Jan 2017 03:14:09 PM CST
 ****************************************************************************************
 */

#define MOUDLE_OPTEE_SAVE_KEY_ENTRY_C_

/** @defgroup MODULE_NAME_INFOR
* @{
*/

/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "SaveKeyTaType.h"
#include "SaveKeyTaHandle.h"
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
 *- #Description  This function creating the entry point of crypto verify task.
 * @param   void
 *
 * @return     TEE_Result
 * @retval     TEE_SUCCESS
 *
 *
 */
TEE_Result TA_CreateEntryPoint(void)
{
#ifdef DEBUG_ENABLE
    TF("Save key task TA_CreateEntryPoint \n");
#endif
    return TEE_SUCCESS;
}







/** @ingroup MOUDLE_NAME_C_
 *- #Description  This function openning the session of crypto verify task.
 * @param   void
 *
 * @return     TEE_Result
 * @retval     TEE_SUCCESS
 *
 *
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[4], void** sessionContext)
{
    TEE_Result ret=TEE_SUCCESS;
    (void)paramTypes;
    (void)params;
    (void)sessionContext;
#ifdef DEBUG_ENABLE
    TF("Save key task TA_OpenSessionEntryPoint\n");
#endif
    return ret;
}



/** @ingroup MOUDLE_NAME_C_
 *- #Description  This function closing the seccsion of crypto verify task.
 * @param   void
 *
 * @return     TEE_Result
 * @retval     TEE_SUCCESS
 *
 *
 */
void TA_CloseSessionEntryPoint(void* session_context)
{
#ifdef DEBUG_ENABLE
    TF("Save key task TA_CloseSessionEntryPoint\n");
#endif
    (void)session_context;
}



/** @ingroup MOUDLE_NAME_C_
 *- #Description  This function for destroying the task of crypto verify.
 * @param   void
 *
 * @return     TEE_Result
 * @retval     TEE_SUCCESS
 *
 *
 */

void TA_DestroyEntryPoint(void)
{
#ifdef DEBUG_ENABLE
    TF("Save key task TA_DestroyEntryPoint\n");
#endif
}







/** @ingroup MOUDLE_NAME_C_
 *- #Description  This function for handling the command in crypto verify task.
 * @param   void
 *
 * @return     TEE_Result
 * @retval     TEE_SUCCESS
 *
 *
 */
TEE_Result TA_InvokeCommandEntryPoint(void* session_context, uint32_t cmd_id, uint32_t paramTypes, TEE_Param params[4])
{
    TEE_Result l_ret = TEE_SUCCESS;
    int l_RetVal = FAIL;

    (void)session_context;

    /** 1) Handle the CA request message according to command index
    *      - EN_CMD_AES_KEY_GET: Get the aes boot key;
    *      - Default:            discard the message */
    switch(cmd_id)
    {
        /* this case for analyzing input data & encrypt device ID by cpuid */
        case CMD_SAVE_KEYDATA_ID:
            #ifdef DEBUG_ENABLE
            TF("#######~~~~~~~~~ENTRY save Save key in EMMC command~~~~~~~~~#######\n");
            #endif
            l_RetVal= g_SaveKeyTa_SaveData(paramTypes, params);
            break;
        case CMD_SAVE_KEY_GET:
            #ifdef DEBUG_ENABLE
            TF("#######~~~~~~~~~ENTRY GET key in EMMC command~~~~~~~~~#######\n");
            #endif
            l_RetVal= g_SaveKeyTa_GetKey(paramTypes, params);
            break;
        default:
            l_RetVal = FAIL;
            break;
    }

    /**2) Check if the crypto operation is successful */
    if(FAIL == l_RetVal)
    {
        l_ret = TEE_FAIL;
    }
    else
    {
        l_ret = TEE_SUCCESS;
    }

    /**3) Return the result */
    return  l_ret;
}




















/**
 * @}
 */
