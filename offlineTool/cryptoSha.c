/*
 ****************************************************************************************
 *
 *               cryptoSha.c
 *
 * Filename      : cryptoSha.c
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.com
 * Create Time   : Thu 20 Aug 2015 03:02:00 AM EDT
 ****************************************************************************************
 */

#define MOUDLE_SHA_C_

/** @defgroup MODULE_NAME_INFOR
* @{
*/

/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "cryptoType.h"
#include "cryptoSha.h"
#include "cryptoDebug.h"




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
void g_CryptoSha_shaOper(EN_SHA_MODE shaMode, CHAR* pInput, UINT32 inLen, CHAR* pOutput)
{
    switch(shaMode)
    {
        case EN_OP_SHA1:
            SHA1(pInput, inLen, pOutput);
            break;
        case EN_OP_SHA224:
            SHA224(pInput, inLen, pOutput);
            break;        
        case EN_OP_SHA256:
            SHA256(pInput, inLen, pOutput);
            break;        
        case EN_OP_SHA384:
            SHA384(pInput, inLen, pOutput);
            break;        
        case EN_OP_SHA512:
            SHA512(pInput, inLen, pOutput);
            break;        
        default:
            printf("ERROR: invalid sha mode\n");
            break;        
    }
}



















/**
 * @}
 */
