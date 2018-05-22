/*
 ****************************************************************************************
 *
 *               SaveKeyTaPbkdf2.h
 *
 * Filename      : SaveKeyTaPbkdf2.h
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.com
 * Create Time   : Wed 04 Jan 2017 03:15:43 PM CST
 ****************************************************************************************
 */

#ifndef MOUDLE_OPTEE_SAVE_KEY_PBKDF2_H_
#define MOUDLE_OPTEE_SAVE_KEY_PBKDF2_H_




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


#ifndef MOUDLE_OPTEE_SAVE_KEY_PBKDF2_C_


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
extern int g_SaveKeyTaHash_pbkdf2(CHAR* output, UINT32 OutLen, CHAR* passWd, UINT32 passLen, CHAR* salt, UINT32 saltLen, UINT32 count);




















#endif

#endif  /* MOUDLE_NAME_H*/
