/*
 ****************************************************************************************
 *
 *                 SaveKeyTaSecStor.h
 *
 * Filename      : SaveKeyTaSecStor.h
 * Programmer(s) : China Security CE team
 * Filename      : SaveKeyTaSecStor.h
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.com
 * Create Time   : 2018年05月22日 星期二 20时32分20秒
 ****************************************************************************************
 */

#ifndef MOUDLE_OPTEE_SAVE_KEY_SECSTOR_H_
#define MOUDLE_OPTEE_SAVE_KEY_SECSTOR_H_




/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/





/*
 *******************************************************************************
 *                  MACRO DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/
#define FILE_NAME "SaveKeyFile"




/*
 *******************************************************************************
 *                STRUCTRUE DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/
#define   TEE_ALG_INVALID 0x0000FFFF
#define TEE_EXEC_FAIL   0x0000FFFF
#define TEE_OBJECT_STORAGE_PRIVATE  0x00000001


#ifndef MOUDLE_OPTEE_SAVE_KEY_SECSTOR_C_


/*
 *******************************************************************************
 *                      VARIABLES SUPPLIED BY THIS MODULE
 *******************************************************************************
*/





/*
 *******************************************************************************
 *                      FUNCTIONS SUPPLIED BY THIS MODULE
 *******************************************************************************
*/
extern TEE_Result g_SecStorTa_Read(CHAR* buf, UINT32 len);
extern TEE_Result g_SecStorTa_Write(CHAR* buf, UINT32 len);
extern TEE_Result g_SecStorTa_CreateFile(void);



















#endif

#endif  /* MOUDLE_NAME_H*/
