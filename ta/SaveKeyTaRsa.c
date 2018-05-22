/*
 ****************************************************************************************
 *
 *               SaveKeyTaRsa.c
 *
 * Filename      : SaveKeyTaRsa.c
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.com
 * Create Time   : Wed 04 Jan 2017 03:14:50 PM CST
 ****************************************************************************************
 */

#define MOUDLE_OPTEE_SAVE_KEY_RSA_C_

/** @defgroup MODULE_NAME_INFOR
* @{
*/

/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "SaveKeyTaRsa.h"
#include "SaveKeyTaDebug.h"
#include "SaveKeyTaHash.h"




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
void l_SaveKeyTaRsa_CleanUpPublicHandle(void);
int l_SaveKeyTaRsa_SetRsaPublicKey(void);
int g_SaveKeyTaRsa_rsaVerify(CHAR* inBuf, UINT32 inLen);





/*
 *******************************************************************************
 *                          VARIABLES USED ONLY BY THIS MODULE
 *******************************************************************************
*/
CHAR g_Rsa2048_N[] = 
{
    0xc6, 0x23, 0x15, 0x60, 0xd5, 0xf5, 0x34, 0x1a, 0xd9, 0xa0, 0x1a, 0x55, 0x4f, 0x04,
    0xfb, 0x2f, 0x83, 0x42, 0x90, 0x71, 0x73, 0xb0, 0xa3, 0xf1, 0x33, 0xbd, 0x21, 0x59, 0x9c, 
    0xff, 0x87, 0xd1, 0xda, 0x49, 0xdb, 0xe2, 0xa5, 0xd1, 0xb3, 0x88, 0x36, 0xdf, 0xea, 0x54, 
    0xc0, 0x53, 0x27, 0xae, 0x02, 0x5a, 0xce, 0x17, 0x40, 0xd7, 0x01, 0x44, 0xaf, 0xff, 0xbf, 
    0x28, 0x3b, 0x4c, 0xc9, 0x66, 0x56, 0x36, 0x02, 0xd0, 0x09, 0x15, 0x5e, 0x4c, 0x08, 0x84, 
    0x4c, 0xa5, 0x7a, 0x30, 0x8e, 0x68, 0xff, 0x8d, 0x5a, 0x66, 0x61, 0xcb, 0x16, 0xf3, 0x8b, 
    0x10, 0x6e, 0x5c, 0xff, 0xa6, 0xf3, 0xf3, 0xe9, 0xb3, 0x8f, 0xe7, 0x7d, 0x7d, 0xea, 0x4d, 
    0x98, 0x96, 0x39, 0x45, 0xe5, 0xcf, 0xb6, 0x69, 0x8a, 0xf1, 0x1a, 0xfd, 0xee, 0xb0, 0xa5, 
    0x4b, 0x15, 0x76, 0x1f, 0x7b, 0x95, 0x12, 0x9d, 0x9f, 0x52, 0x2e, 0x8b, 0x3d, 0x5c, 0x41, 
    0x94, 0xbc, 0x16, 0x64, 0xcf, 0x58, 0x61, 0xc8, 0x06, 0xdf, 0xca, 0xeb, 0xf4, 0x82, 0xd0, 
    0x43, 0x62, 0xbc, 0x1e, 0x1c, 0x83, 0xaa, 0xee, 0x8f, 0x47, 0x7f, 0x87, 0xb1, 0x58, 0xee, 
    0xb1, 0x49, 0x56, 0x95, 0x1c, 0xf9, 0x49, 0x8e, 0xa6, 0xa3, 0x5b, 0x77, 0xe6, 0xb4, 0x2e, 
    0xeb, 0x96, 0x69, 0x00, 0xb6, 0xc2, 0xbb, 0xbd, 0x50, 0xbf, 0x6a, 0x15, 0xb0, 0x35, 0xc9, 
    0x67, 0x70, 0x6c, 0xaf, 0xd5, 0xfa, 0x9f, 0xbf, 0x2d, 0xaa, 0x8e, 0x81, 0xed, 0x5e, 0x09, 
    0x17, 0x55, 0x32, 0x7d, 0xc7, 0x23, 0x0e, 0x2e, 0xd3, 0xa5, 0x36, 0xcf, 0xc1, 0x80, 0xab, 
    0x37, 0x62, 0x05, 0xb4, 0x8b, 0x10, 0xe7, 0x4e, 0x83, 0x80, 0x06, 0xf4, 0x2e, 0x91, 0x44, 
    0xff, 0x2c, 0x9a, 0xc9, 0x99, 0x6c, 0x44, 0x83, 0x65, 0x3e, 0xcb, 0xa5, 0x0d, 0x9f, 0x5f, 
    0xf1, 0x79
};
int g_Rsa2048Len_N = 256;


CHAR g_Rsa2048_E[] = 
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01
};
int g_Rsa2048Len_E = 256;


UINT32 g_MaxKeySize = 0U;
TEE_OperationHandle g_pOperationHandle = TEE_HANDLE_NULL;

TEE_ObjectHandle g_PublicKeyObjHandle = TEE_HANDLE_NULL;
TEE_Attribute g_PublicKeyAttr[2];

char g_test[] =
{
    0x26, 0xb2, 0x48, 0x45, 0x08, 0x87, 0x8d, 0xfe, 0x83, 0x42, 0x03, 0x51, 0x47, 0x6a, 0x03, 0xd5, 
    0x2c, 0xdb, 0x97, 0xe6, 0x8e, 0x00, 0xb6, 0x54, 0xc8, 0x75, 0x4a, 0xf2, 0x4f, 0x44, 0x74, 0xcc, 
    0xfb, 0xae, 0x31, 0x47, 0xba, 0x5d, 0x67, 0x70, 0xee, 0x90, 0x01, 0x07, 0x47, 0x47, 0x08, 0x36, 
    0xef, 0xee, 0xcd, 0x47, 0xfd, 0x37, 0x70, 0xfa, 0x44, 0xbe, 0xb1, 0xc1, 0xdb, 0x02, 0x81, 0xb7, 
    0xdf, 0xa6, 0x8d, 0xf1, 0xf5, 0xc8, 0xe6, 0x0c, 0x4d, 0x03, 0xb3, 0x61, 0xf4, 0x0c, 0x70, 0xd0, 
    0x94, 0x15, 0x8a, 0xc6, 0x07, 0x9a, 0x4f, 0xf9, 0x59, 0xfc, 0x25, 0x0d, 0x7c, 0xda, 0x84, 0xfb, 
    0x1e, 0xac, 0xb8, 0x09, 0x9c, 0xfa, 0x68, 0x74, 0x7d, 0x38, 0xde, 0x31, 0x70, 0xb9, 0x91, 0xdb, 
    0x52, 0x6f, 0x23, 0x99, 0x53, 0xc9, 0xaa, 0xea, 0x94, 0x60, 0xf0, 0x62, 0x24, 0xf6, 0x67, 0xee, 
    0x54, 0xaf, 0x94, 0xd8, 0x27, 0xae, 0x03, 0x02, 0x4a, 0x08, 0xa8, 0x3a, 0xa4, 0x7e, 0xda, 0x97, 
    0x60, 0x44, 0xee, 0x29, 0x9b, 0x17, 0xba, 0x77, 0x02, 0x68, 0x0c, 0xed, 0x44, 0xe7, 0x1b, 0x3a, 
    0x93, 0x62, 0x96, 0x67, 0x3a, 0x7b, 0x08, 0x79, 0x52, 0x7a, 0x84, 0xc5, 0x16, 0x9e, 0x7e, 0x96, 
    0xd8, 0x35, 0x24, 0x98, 0x66, 0xb5, 0x0f, 0x90, 0x6b, 0xc4, 0x85, 0x8d, 0xc9, 0x9a, 0x11, 0xcd, 
    0x4a, 0x39, 0xb0, 0x40, 0x7e, 0x4b, 0xfd, 0x18, 0x3d, 0x4d, 0xd3, 0x0a, 0x80, 0x02, 0x8a, 0x5d, 
    0x35, 0x7c, 0xed, 0x44, 0xa7, 0x38, 0xcf, 0x67, 0x75, 0xa1, 0xb3, 0x5f, 0xdf, 0xb6, 0x24, 0x17, 
    0xdc, 0xd1, 0xd0, 0xbf, 0x05, 0xe6, 0x70, 0xc2, 0x87, 0xfc, 0x60, 0x7f, 0x7a, 0xb0, 0x16, 0xc2, 
    0x85, 0xcf, 0x40, 0x79, 0xea, 0x6f, 0x17, 0xb0, 0xe7, 0xc1, 0x75, 0xa0, 0x98, 0xe3, 0x14, 0x30
};

/*
 *******************************************************************************
 *                               FUNCTIONS IMPLEMENT
 *******************************************************************************
*/
void l_SaveKeyTaRsa_CleanUpPublicHandle(void)
{
    if(TEE_HANDLE_NULL != g_PublicKeyObjHandle)
    {
        TEE_FreeTransientObject(g_PublicKeyObjHandle);
    }

    if(TEE_HANDLE_NULL != g_pOperationHandle)
    {
        TEE_FreeOperation(g_pOperationHandle);
    }
}



int l_SaveKeyTaRsa_SetRsaPublicKey(void)
{
    TEE_Result l_TeeRetVal = TEE_FAIL;
    int l_Result = OK;

    /** 1) Set the max size of key */
    g_MaxKeySize = g_Rsa2048Len_N*8U;

    /** 2) Clean attribute array */
    TEE_MemFill(g_PublicKeyAttr, 0, 2*(sizeof(TEE_Attribute)));
    
    /** 3) Set attribute[0] data with N data */
    g_PublicKeyAttr[0].attributeID = TEE_ATTR_RSA_MODULUS;
    g_PublicKeyAttr[0].content.ref.buffer = g_Rsa2048_N;
    g_PublicKeyAttr[0].content.ref.length = g_Rsa2048Len_N;

    /** 4) Set attribute[1] data with E data */
    g_PublicKeyAttr[1].attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT;
    g_PublicKeyAttr[1].content.ref.buffer = g_Rsa2048_E;
    g_PublicKeyAttr[1].content.ref.length = g_Rsa2048Len_E; 

    /** 5) Allocate the public key handle */
    l_TeeRetVal = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY, g_MaxKeySize, &g_PublicKeyObjHandle);
    if(TEE_SUCCESS != l_TeeRetVal)
    {
    #ifdef DEBUG_ENABLE
        TF("Do allocate obj handle fail, Ret value is:0x%x\n", l_TeeRetVal);
    #endif
        l_Result = FAIL;
        goto done;
    }

    /** 6) Populate the attribute */
    l_TeeRetVal = TEE_PopulateTransientObject(g_PublicKeyObjHandle, g_PublicKeyAttr, 2);
    if(TEE_SUCCESS != l_TeeRetVal)
    {
    #ifdef DEBUG_ENABLE
        TF("Do populate obj handle fail, Ret value is:0x%x\n", l_TeeRetVal);
    #endif
        l_Result = FAIL;
        goto cleanUp1;
    }

    /** 7) Return the operation result */
    return l_Result;

    /* Do clean up operation when have some operation faile */
cleanUp1:
    TEE_FreeTransientObject(g_PublicKeyObjHandle);
    g_PublicKeyObjHandle = TEE_HANDLE_NULL;
done:
    return l_Result;
}




int g_SaveKeyTaRsa_rsaVerify(CHAR* inBuf, UINT32 inLen)
{
    TEE_Result l_TeeRetVal = TEE_FAIL;
    int l_Result = FAIL;
    CHAR l_Hash[20] = {0};
    //UINT32 l_HashLen = 20U;
    UINT32 l_OutLen = inLen;
    CHAR dataBuf[106] = {0};
    CHAR signature[256] = {0};

    TEE_MemMove(dataBuf, inBuf, 106);
    TEE_MemMove(signature, &(inBuf[106]), 256);
#ifdef DEBUG_ENABLE
    TF("The input length is :%d\n", inLen);
    TF("The signature info just like follow:\n");
    g_TA_Printf(inBuf, inLen);
#endif

    /** 1) Calculate hash value of input data */
    g_SaveKeyTaHash_sha(inBuf, inLen-256, l_Hash, &inLen);

#ifdef DEBUG_ENABLE
    TF("The output hash valus is\n");
    g_TA_Printf(l_Hash, inLen);
#endif

    /** 2) Set the public key object handle */
    l_Result = l_SaveKeyTaRsa_SetRsaPublicKey();
    if(FAIL == l_Result)
    {
    #ifdef DEBUG_ENABLE
        TF("[verify]Set public key object handle faile!\n");
    #endif
        goto done;
    }

    /** 3) Allocate the operation handle */
    l_TeeRetVal = TEE_AllocateOperation(&g_pOperationHandle, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_VERIFY, g_MaxKeySize);
    if(TEE_SUCCESS != l_TeeRetVal)
    {
    #ifdef DEBUG_ENABLE
        TF("[verify]The allocate operate handle fail, the return value is: 0x%x\n", l_TeeRetVal);
    #endif
        l_Result = FAIL;
        goto done;
    }

    /** 4) Assemble the key object into operation handle */
    l_TeeRetVal = TEE_SetOperationKey(g_pOperationHandle, g_PublicKeyObjHandle);
    if(TEE_SUCCESS != l_TeeRetVal)
    {
    #ifdef DEBUG_ENABLE
        TF("[verify]Set operation key faile, return value is:0x%x\n", l_TeeRetVal);
    #endif
        l_Result = FAIL;
        goto cleanUp_1;
    } 

    /** 5) Do cipher operation, judge the operation mode to do encrypto or decrypt */
#ifdef DEBUG_ENABLE
    TF("The index is:%d\n", (l_OutLen - 256U));
    //g_TA_Printf(&(inBuf[l_OutLen - 256U]), 256);
#endif

    l_TeeRetVal = TEE_AsymmetricVerifyDigest(g_pOperationHandle, NULL, 0, inBuf, 20, signature, 256);
    if(TEE_SUCCESS != l_TeeRetVal)
    {
    #ifdef DEBUG_ENABLE
        TF("Verify faile\n");
    #endif
        l_Result = FAIL;
    }
    else
    {
        TF("Verify success!\n");
        l_Result = OK;
    }

cleanUp_1:
    TEE_FreeOperation(g_pOperationHandle);
    g_pOperationHandle = TEE_HANDLE_NULL;
done:
    l_SaveKeyTaRsa_CleanUpPublicHandle();
    return l_Result;
}

















/**
 * @}
 */