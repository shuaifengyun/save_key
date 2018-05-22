/*
 ****************************************************************************************
 *
 *               SaveKeyCa.c
 *
 * Filename      : SaveKeyCa.c
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.com
 * Create Time   : Tue 19 Apr 2017 05:22:37 PM CST
 ****************************************************************************************
 */

#define MOUDLE_SAVE_KEY_CA_C_

/** @defgroup MODULE_NAME_INFOR
* @{
*/

/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "SaveKeyCa.h"
#include "SaveKeyCaDebug.h"






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
static BOOL g_TaskInitFlag = FALSE_CA;    /* Flag if the task done initialize operation */
static BOOL g_OpenSessionFlag = FALSE_CA;    /* Flag if the task done initialize operation */
TEEC_UUID svc_id = DEVICE_ID_UUID;
TEEC_Context g_TaskContext;
TEEC_Session   g_session;    /* Define the session of TA&CA */




/*
 *******************************************************************************
 *                               FUNCTIONS IMPLEMENT
 *******************************************************************************
*/






int l_SaveKeyCa_TaskInit(void)
{
    TEEC_Result result;
    int l_RetVal = OK;
    
    /**1) Check if need to do task initialization operation */
    if(FALSE_CA == g_TaskInitFlag)
    {
        result = TEEC_InitializeContext(NULL, &g_TaskContext);
        if(result != TEEC_SUCCESS) 
        {
            TF("InitializeContext failed, ReturnCode=0x%x\n", result);
            l_RetVal= FAIL;
        } 
        else 
        {
            g_TaskInitFlag = TRUE_CA;
            TF("InitializeContext success\n");
            l_RetVal = OK;
        }
    }
    
    return l_RetVal;
}


int l_SaveKeyCa_OpenSession(TEEC_Session* session)
{
    TEEC_Result result;
    int l_RetVal = FAIL;
    uint32_t origin;

    if(FALSE_CA == g_OpenSessionFlag)
    {
        result = TEEC_OpenSession(&g_TaskContext, session, &svc_id, 
                                    TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
        if(result != TEEC_SUCCESS) 
        {
            //TF("OpenSession failed, ReturnCode=0x%x, ReturnOrigin=0x%x\n", result, origin);
            g_TaskInitFlag = FALSE_CA;
            l_RetVal = FAIL;
        } 
        else 
        {
            //TF("OpenSession success\n");
            g_OpenSessionFlag = TRUE_CA;
            l_RetVal = OK;
        }
    }
    else
    {
        l_RetVal = OK;
    }

    return l_RetVal;
}


int l_SaveKeyCa_SendCommand(TEEC_Operation* operation, TEEC_Session* session, uint32_t commandID)
{
    TEEC_Result result;
    int l_RetVal = FAIL;
    uint32_t origin;

    result = TEEC_InvokeCommand(session, commandID, operation, &origin);
    if (result != TEEC_SUCCESS) 
    {
        //TF("InvokeCommand failed, ReturnCode=0x%x, ReturnOrigin=0x%x\n", result, origin);
        l_RetVal = FAIL;
    } 
    else 
    {
        //TF("InvokeCommand success\n");
        l_RetVal = OK;
    }


    return l_RetVal;
}









/** @ingroup MODULE_MANAGE_KEY_CA
 *- #Description  This function for sending request to TA, then save key data into secure memory.
 * @param   keyDataBuf    [IN,OUT] Struct of input buffer, which include the information of data 
 *                                  need to be decrypt by TEE & saved in secure memory
 *                               - Type: SaveData
 *                               - Range: N/A.
 *
 * @return     int
 * @retval      OK: Send CA request is OK
 * @retval    FAIL: Send CA request is fail
 *
 *
 */
int g_SaveKeyCa_KeepKeyData(KeepKeyData input)
{
    TEEC_Operation l_operation;  /* Define the operation for communicating between TA&CA */
    int l_RetVal = FAIL;       /* Define the return value of function */

    /**1) Initialize this task */
    l_RetVal = l_SaveKeyCa_TaskInit();
    if(FAIL == l_RetVal)
    {
        goto cleanup_1;
    }

    /**2) Open session */
    l_RetVal = l_SaveKeyCa_OpenSession(&g_session);
    if(FAIL == l_RetVal)
    {
        goto cleanup_2;
    }

    /**3) Set the communication context between CA&TA */
    memset(&l_operation, 0x0, sizeof(TEEC_Operation));
    l_operation.started = 1;
    l_operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, 
                                              TEEC_NONE, TEEC_NONE);
    l_operation.params[0].tmpref.size = input.messageLen;
    l_operation.params[0].tmpref.buffer = input.pMessage;
    g_CA_PrintfBuffer(l_operation.params[0].tmpref.buffer, l_operation.params[0].tmpref.size);

    /**4) Send command to TA */    
    l_RetVal = l_SaveKeyCa_SendCommand(&l_operation, &g_session, CMD_SAVE_KEYDATA_ID);
    //TF("The respond data length is %d\n", input.outLen);
    //g_CA_PrintfBuffer(input.outBuf, input.outLen);
    if(FAIL == l_RetVal)
    {
        goto cleanup_3;
    }
    else
    {
        goto cleanup_1;
    }

    /**5) The clean up operation */
cleanup_3:
    //TF("Close session!!!!\n");
    TEEC_CloseSession(&g_session);
    g_OpenSessionFlag = FALSE_CA;
cleanup_2:
    //TF("free context!!!!\n");
    TEEC_FinalizeContext(&g_TaskContext);
    g_TaskInitFlag = FALSE_CA;
cleanup_1:
    return l_RetVal;
}












/** @ingroup MODULE_MANAGE_KEY_CA
 *- #Description  This function for sending request to TA, then save key data into secure memory.
 * @param   keyDataBuf    [IN,OUT] Struct of input buffer, which include the information of data 
 *                                  need to be decrypt by TEE & saved in secure memory
 *                               - Type: SaveData
 *                               - Range: N/A.
 *
 * @return     int
 * @retval      OK: Send CA request is OK
 * @retval    FAIL: Send CA request is fail
 *
 *
 */
int g_SaveKeyCa_GetKey(CHAR* pOut, UINT32 len)
{
    TEEC_Operation l_operation;  /* Define the operation for communicating between TA&CA */
    int l_RetVal = FAIL;       /* Define the return value of function */

    /**1) Initialize this task */
    l_RetVal = l_SaveKeyCa_TaskInit();
    if(FAIL == l_RetVal)
    {
        goto cleanup_1;
    }

    /**2) Open session */
    l_RetVal = l_SaveKeyCa_OpenSession(&g_session);
    if(FAIL == l_RetVal)
    {
        goto cleanup_2;
    }

    /**3) Set the communication context between CA&TA */
    memset(&l_operation, 0x0, sizeof(TEEC_Operation));
    l_operation.started = 1;
    l_operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, 
                                              TEEC_NONE, TEEC_NONE);
    l_operation.params[0].tmpref.size = len;
    l_operation.params[0].tmpref.buffer = pOut;

    /**4) Send command to TA */    
    l_RetVal = l_SaveKeyCa_SendCommand(&l_operation, &g_session, CMD_SAVE_KEY_GET);
    //TF("The respond data length is 0x%02x\n", len);
    //g_CA_PrintfBuffer(pOut, len);
    if(FAIL == l_RetVal)
    {
        goto cleanup_3;
    }
    else
    {
        goto cleanup_1;
    }

    /**5) The clean up operation */
    cleanup_3:
        TEEC_CloseSession(&g_session);
        g_OpenSessionFlag = FALSE_CA;
        //TF("close session!!!!\n");
    cleanup_2:
        TEEC_FinalizeContext(&g_TaskContext);
        g_TaskInitFlag = FALSE_CA;
        //TF("free context!!!!\n");
    cleanup_1:
        return l_RetVal;
}











/**
 * @}
 */
