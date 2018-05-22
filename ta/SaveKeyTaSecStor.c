/*
 ****************************************************************************************
 *
 *                 SaveKeyTaSecStor.c
 *
 * Filename      : SaveKeyTaSecStor.c
 * Programmer(s) : China Security CE team
 * Filename      : SaveKeyTaSecStor.c
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.com
 * Create Time   : 2018年05月22日 星期二 20时32分08秒
 ****************************************************************************************
 */

#define MOUDLE_OPTEE_SAVE_KEY_SECSTOR_C_

/** @defgroup MODULE_NAME_INFOR
* @{
*/

/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "SaveKeyTaType.h"
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
static TEE_Result l_SecStorTa_Open(CHAR* fileName, UINT32 fileNameSize);
TEE_Result g_SecStorTa_Read(CHAR* buf, UINT32 len);
TEE_Result g_SecStorTa_Write(CHAR* buf, UINT32 len);
TEE_Result g_SecStorTa_CreateFile(void);




/*
 *******************************************************************************
 *                          VARIABLES USED ONLY BY THIS MODULE
 *******************************************************************************
*/
TEE_ObjectHandle g_FilesObj;





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



static TEE_Result l_SecStorTa_Open(CHAR* fileName, UINT32 fileNameSize)
{
    TEE_Result l_ret = TEE_EXEC_FAIL; 
    UINT32 l_AccFlg = TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_READ;


    l_ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, fileName, 
                                   fileNameSize, l_AccFlg, (&g_FilesObj));
    if (TEE_SUCCESS != l_ret)
    {        
        return TEE_EXEC_FAIL;
    }
    else
    {
        return TEE_SUCCESS;
    }
}

TEE_Result g_SecStorTa_CreateFile(void)
{
    TEE_Result l_ret = TEE_EXEC_FAIL;
    UINT32 l_fileNameSize = 0U;
    CHAR l_FileName[] = FILE_NAME;
    l_fileNameSize = sizeof(l_FileName);

    TF("[CREATE] start to create file: %s\n", l_FileName);
    l_ret = TEE_CreatePersistentObject(TEE_OBJECT_STORAGE_PRIVATE, l_FileName,
                       l_fileNameSize, TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_ACCESS_WRITE, 
                       TEE_HANDLE_NULL , NULL, 0, 
                       (&g_FilesObj));
    if (TEE_SUCCESS != l_ret)
    {
        TF("[CREATE] create file fail");
        return TEE_EXEC_FAIL;
    }
    else
    {
        TEE_CloseObject(g_FilesObj);
        return TEE_SUCCESS;
    }
}


TEE_Result g_SecStorTa_Read(CHAR* buf, UINT32 len)
{
    TEE_Result l_ret = TEE_SUCCESS;
    CHAR* l_OutBuf = NULL;
    UINT32 l_ReadLen = 0U;
    CHAR l_FileName[] = FILE_NAME;
    UINT32 l_Count = 0U;
    
    /** 1) Get the fd of secure file */
    l_OutBuf = buf;
    l_ReadLen = len;

    TF("[READ] start to read file: %s\n", l_FileName);
    l_ret = l_SecStorTa_Open(l_FileName, sizeof(l_FileName));
    if (TEE_SUCCESS != l_ret)
    {        
        TF("[READ] open file fail\n");
        return TEE_EXEC_FAIL;
    }

    /** 2) Start read data from secure file */
    l_ret = TEE_ReadObjectData(g_FilesObj, l_OutBuf, l_ReadLen, &l_Count);

    TEE_CloseObject(g_FilesObj);
    if (TEE_SUCCESS != l_ret)
    {        
        TF("[READ] read file fail\n");
        return TEE_EXEC_FAIL;
    }
    else
    {
        return TEE_SUCCESS;
    }
}


TEE_Result g_SecStorTa_Write(CHAR* buf, UINT32 len)
{
    TEE_Result l_ret = TEE_SUCCESS;
    CHAR* l_InBuf = NULL;
    UINT32 l_WriteLen = 0U;
    CHAR l_FileName[] = FILE_NAME;
    
    /** 1) Get the fd of secure file */
    l_InBuf = buf;
    l_WriteLen = len;

    TF("[WRITE] start to write file: %s, %d\n", l_FileName, sizeof(l_FileName));
    l_ret = l_SecStorTa_Open(l_FileName, sizeof(l_FileName));
    if (TEE_SUCCESS != l_ret)
    {     
        TF("[WRITE] open file fail\n");
        return TEE_EXEC_FAIL;
    }

    /** 2) Start read data from secure file */
    l_ret = TEE_WriteObjectData(g_FilesObj, l_InBuf, l_WriteLen);

    TEE_CloseObject(g_FilesObj);
    if (TEE_SUCCESS != l_ret)
    {        
        TF("[WRITE] wtire file fail\n");
        return TEE_EXEC_FAIL;
    }
    else
    {
        return TEE_SUCCESS;
    }
}












/**
 * @}
 */
