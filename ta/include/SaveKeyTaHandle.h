/*
 ****************************************************************************************
 *
 *               SaveKeyTaHandle.h
 *
 * Filename      : SaveKeyTaHandle.h
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.com
 * Create Time   : Wed 04 Jan 2017 03:15:28 PM CST
 ****************************************************************************************
 */

#ifndef MOUDLE_OPTEE_SAVE_KEY_HANDLE_H_
#define MOUDLE_OPTEE_SAVE_KEY_HANDLE_H_




/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "SaveKeyTaType.h"
#include "SaveKeyTaDebug.h"





/*
 *******************************************************************************
 *                  MACRO DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/





/*
 *******************************************************************************
 *                STRUCTRUE DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/


#ifndef MOUDLE_OPTEE_SAVE_KEY_HANDLE_C_


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
extern int g_SaveKeyTa_SaveData(uint32_t paramTypes, TEE_Param params[4]);
extern int g_SaveKeyTa_GetKey(uint32_t paramTypes, TEE_Param params[4]);




















#endif

#endif  /* MOUDLE_NAME_H*/
