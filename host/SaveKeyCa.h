/*
 ****************************************************************************************
 *
 *               SaveKeyCa.h
 *
 * Filename      : SaveKeyCa.h
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.con
 * Create Time   : Wed 11 Nov 2016 03:10:52 PM CST
 ****************************************************************************************
 */

#ifndef MOUDLE_SAVE_KEY_CA_H_
#define MOUDLE_SAVE_KEY_CA_H_




/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "tee_client_api.h"
#include <unistd.h>









/*
 *******************************************************************************
 *                  MACRO DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/
#define DEVICE_ID_UUID \
            { 0xfe93c771, 0xc349, 0x492e, \
            { 0x89, 0xce, 0x21, 0x8f, 0x4e, 0xb6, 0xff, 0xa9 } }


/* Define the comman ID */
#define CMD_SAVE_KEYDATA_ID                   1U     /**< Command ID for save device ID */
#define CMD_SAVE_KEY_GET                    2U     /**< Command ID for get device ID */






/* Define the return value of function */
#define FAIL -1
#define OK   0

#define FALSE_CA   -1
#define TRUE_CA     0







/*
 *******************************************************************************
 *                STRUCTRUE DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/
/* Define the type of variable */
typedef unsigned char  UINT8;    /**< Typedef for 8bits unsigned integer  */
typedef unsigned short UINT16;   /**< Typedef for 16bits unsigned integer */
typedef unsigned int   UINT32;   /**< Typedef for 32bits unsigned integer */
typedef signed char    INT8;     /**< Typedef for 8bits signed integer    */
typedef signed short   INT16;    /**< Typedef for 16bits signed integer   */
typedef signed int     INT32;    /**< Typedef for 32bits signed integer   */
typedef char           CHAR;     /**< Typedef for char                    */
typedef int BOOL;


/**< The struct of encrypting data */
typedef struct KeepKeyData_s
{
    CHAR* pMessage;           /* Point to the data which will be decrypted & saved in secure memory */
    UINT32 messageLen;            /* Length of the input data , will be done AES operation  */
}KeepKeyData;




#ifndef MOUDLE_SAVE_KEY_CA_C_


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
extern int g_SaveKeyCa_KeepKeyData(KeepKeyData input);
extern int g_SaveKeyCa_GetKey(CHAR* pOut, UINT32 len);















#endif

#endif  /* MOUDLE_NAME_H*/
