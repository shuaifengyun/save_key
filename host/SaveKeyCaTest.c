/*
 ****************************************************************************************
 *
 *               SaveKeyCaTest.c
 *
 * Filename      : SaveKeyCaTest.c
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.com
 * Create Time   : Thu 12 Nov 2017 04:05:30 PM CST
 ****************************************************************************************
 */



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

CHAR g_Message[] = "Mn4qO7I9NhlVEqYrBPpC+cegDvRfNoDswEvWxYP1HQp0uW7hxH1giYj5ihlhtfZF3bjPT9StrbbP70cRO0cvxayPt/Knc26lyJUMRbVR7EbEfh7oytiDY9fqoiSM0i8F15uy8a6fQ1k6/Gb049Q57qUU/2yQ3k2x9jbIhS1wkH+NKHbcIVtrJHWQ0KiLwZcU";
CHAR g_TeeOutBuf[32] = {0};
















/*
 *******************************************************************************
 *                               FUNCTIONS IMPLEMENT
 *******************************************************************************
*/






void l_Test_saveKeyData(KeepKeyData* input)
{
    input->messageLen = strlen(g_Message);
    input->pMessage = g_Message;
}



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
int main(int argc, char *argv[])
{
    KeepKeyData l_keepData;
    
    if(0 == memcmp(argv[1], "save", 4))
    {
        l_Test_saveKeyData(&l_keepData);
        printf("The input message leng is:%d\n",l_keepData.messageLen);
        g_SaveKeyCa_KeepKeyData(l_keepData);
    }

    if(0 == memcmp(argv[1], "get", 3))
    {
        g_SaveKeyCa_GetKey(g_TeeOutBuf, 32U);
        TF("The get device Id is:17\n");
        g_CA_PrintfBuffer(g_TeeOutBuf, 17U);
    }
    
    return 0;
}









/**
 * @}
 */
