/*
 ****************************************************************************************
 *
 *               SaveKeyTaType.h
 *
 * Filename      : SaveKeyTaType.h
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.com
 * Create Time   : Wed 04 Jan 2017 03:16:31 PM CST
 ****************************************************************************************
 */

#ifndef MOUDLE_OPTEE_SAVE_KEY_TYPE_H_
#define MOUDLE_OPTEE_SAVE_KEY_TYPE_H_




/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "tee_internal_api.h"
#include "tee_api_defines.h"
#include "trace.h"
#include "tee_api_defines_extensions.h"
#include "string.h"





/*
 *******************************************************************************
 *                  MACRO DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/
/* Define the return status of each function */
#define   FAIL     -1            /* Return value when operation fail */
#define   OK        0            /* Return value when operation OK */
#define   TEE_FAIL -1
#define   TEE_ALG_INVALID 0x0000FFFF

/* Define the debug flag */
#define DEBUG_ENABLE
#define TF    MSG_RAW


#define CMD_SAVE_KEYDATA_ID                   1U     /**< Command ID for save device ID */
#define CMD_SAVE_KEY_GET                    2U     /**< Command ID for get device ID */




/*
 *******************************************************************************
 *                STRUCTRUE DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/
/* Define the type of variable */
typedef unsigned char  UINT8;    /**< Typedef for 8bits unsigned integer  */
typedef unsigned short UINT16;   /**< Typedef for 16bits unsigned integer */
typedef uint32_t       UINT32;   /**< Typedef for 32bits unsigned integer */
typedef signed char    INT8;     /**< Typedef for 8bits signed integer    */
typedef signed short   INT16;    /**< Typedef for 16bits signed integer   */
typedef signed int     INT32;    /**< Typedef for 32bits signed integer   */
typedef char           CHAR;     /**< Typedef for char                    */

typedef uint32_t       TEE_CRYPTO_ALGORITHM_ID;





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





















#endif  /* MOUDLE_NAME_H*/
