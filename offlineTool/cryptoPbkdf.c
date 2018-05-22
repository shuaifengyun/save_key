/*
 ****************************************************************************************
 *
 *               cryptoPbkdf.c
 *
 * Filename      : cryptoPbkdf.c
 * Author        : Shuai Fengyun
 * Mail          : shuaifengyun@126.com
 * Create Time   : Fri 21 Aug 2015 07:02:09 AM EDT
 ****************************************************************************************
 */

#define MOUDLE_PBKDF_C_

/** @defgroup MODULE_NAME_INFOR
* @{
*/

/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "cryptoType.h"
#include <stdlib.h>
#include <math.h>
#include <stdio.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <dirent.h>
#include "cryptoType.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
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
void l_CryptoPbkdf_PbkdfHMAC(CHAR* text, UINT32 tlen, CHAR* key, UINT32 klen, CHAR* out)
{
    CHAR key_append[64] = {0};
    CHAR stringText[256] = {0};
    CHAR x_Hash[20] = {0};
    UINT32 stringXLen = 64U;
    UINT32 stringYLen = 64U;
    CHAR y_Hash[20] = {0};
    CHAR ipad = 0x36;
    CHAR opad = 0x5c;
    UINT32 index = 0U;
    CHAR X[64] = {0};
    CHAR Y[64] ={0};
    CHAR tmp;

    /**1) Copy input key data into key append */
    if(klen > 64U)
    {
        memcpy(key_append, key, 64U);
    }
    else
    {
        memcpy(key_append, key, klen);
    }

    /**2) Do xor operation */
    for(index = 0U; index < 64U; index++)
    {
        X[index] = key_append[index]^ipad;   
        Y[index] = key_append[index]^opad;
    }

    /**3) Put the X data and text data into stringText */
    for(index = 0U; index < 64U; index++)
    {
        stringText[index] = X[index];
    }

    for(index = 0U; index < tlen; index++)
    {
        stringText[64 + index] = text[index];
        stringXLen++;
    }
    

    /**4) Do the hash operation for stringText */
    SHA1(stringText, stringXLen, x_Hash);
    

    /**5)  */
    for(index = 0U; index < 64U; index++)
    {
        stringText[index] = Y[index];
    }

    for(index = 0U; index < 20; index++)
    {
        stringText[64 + index] = x_Hash[index];
        stringYLen++;
    }
    

    /**6) Do hash operation */
    SHA1(stringText, stringYLen, y_Hash);

    memcpy(out , y_Hash, 20);
}






void g_CryptoPbkdf_PbkdfOperation(CHAR P[],int Plen, CHAR S[], int Slen, int c,int dkLen, CHAR* output)
{
    CHAR tmp_hmac[20] = {0};
    CHAR resultBuf[512] = {0};
    CHAR U_tmp[128] = {0};
    UINT32 uLen = 0U;
    UINT32 l_Lnum = 0U;
    UINT32 l_Rnum = 0U;
    UINT32 indexI = 0U;
    UINT32 indexJ = 0U;
    UINT32 index =0U;

    printf("Pwd:%s\n", P);
    printf("Pwd len:%d\n", Plen);
    printf("Salt:%s\n", S);
    printf("Salt len:%d\n", Slen);
    printf("dkLen:%d\n", dkLen);

    /**1) Do the cail operation for getting loop num of l_Lnum */
    if((0U == dkLen%20U) &&(20U < dkLen))
    {
        l_Lnum = dkLen/20U;
    }
    else
    {
        l_Lnum = (dkLen/20U)+1; // hLen-octets 32/20 = 2 always 
    }


    /**2) Get the number of octest */
    l_Rnum = dkLen -(l_Lnum-1)*20U; // number of octets in the last block (32-20) = 12
    
    for(indexI = 1U; indexI <= l_Lnum; indexI++)
    {			
        /**3) Copyt salt into tmp buffer for do the first HMAC operation */	
        memset(U_tmp, 0, 128);
        memcpy(U_tmp, S, Slen);
        U_tmp[Slen + 3] = indexI;
        uLen = Slen + 4;

        printf("1\n");
        l_CryptoPbkdf_PbkdfHMAC(U_tmp, uLen, P, Plen, tmp_hmac);
        printf("2\n");

        memset(U_tmp, 0, 128U);
        memcpy(U_tmp, tmp_hmac, 20U);
        uLen = 20U;
        
        for(indexJ = 1U; indexJ < c; indexJ++)			// number of iterations (4096)		
        {
            l_CryptoPbkdf_PbkdfHMAC(tmp_hmac, uLen, P, Plen, tmp_hmac);
            for(index = 0U; index < 20U; index++)
            {
                U_tmp[index] = U_tmp[index] ^ tmp_hmac[index];
            }
        }				

        for(index = 0U; index < 20U; index++)
        {
            resultBuf[(indexI - 1U) * 20 + index] = U_tmp[index];
        }
    } 

    /**4) Copy the result data into output buffer */
    memcpy(output, resultBuf, dkLen);
}


/** @ingroup MOUDLE_NAME_C_
 *- #Description  Function for generating random string.
 * @param   buf           [OUT] Point to the buffer for saving output
 *                               - Type: CHAR *
 *                               - Range: N/A.
 * @param   length        [IN] Length of output
 *                               - Type: CHAR *
 *                               - Range: N/A.
 *
 * @return     void
 * @retval     void
 *
 *
 */
void g_CryptoRandom_GenRandomString(CHAR* buf, UINT32 length)
{
    UINT32 l_Index = 0U;
    UINT32 l_Flag = 0U;
    struct timeval tpstart;

    /**1) Set random seed */
    gettimeofday(&tpstart,NULL);
    srand(tpstart.tv_usec);

    /**2) Generate random & cut out the value which less than 255 */
    for(l_Index = 0; l_Index < length; l_Index++)
    {
        buf[l_Index] = rand() % 0xFFU;
    }
}



void g_Test_hmac(int len)
{
    CHAR l_PwdBuf[18] = "Password22icyshuai";
    CHAR l_SaltBuf[22] = "itsMEjessica22icyshuai";
#if 0
    CHAR l_PwdBuf[18] = {
    0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0x2a, 0x2b, 0x2c, 0xba, 0x4a, 0x6e, 0xb9, 
    0xef, 0xf2};
    CHAR l_SaltBuf[63] = { 
    0x8b, 0x6d, 0xda, 0x43, 0xde, 0x36, 0xc9, 0x1d, 0xa5, 0x08, 0x41, 0x48, 0x5c, 0xce, 0xa1, 0x7c, 
    0x6e, 0xda, 0xa6, 0x8e, 0x83, 0xa0, 0x01, 0x52, 0x74, 0x38, 0x3c, 0x52, 0x1b, 0xf3, 0x8b, 0x53, 
    0xd7, 0xc4, 0xeb, 0x63, 0x3e, 0x8d, 0x8d, 0x29, 0x54, 0x66, 0xd5, 0x6f, 0xfa, 0x93, 0xc4, 0xd8, 
    0x02, 0xec, 0x8d, 0x64, 0x1e, 0x9b, 0x65, 0xad, 0x6c, 0x38, 0x4a, 0x15, 0xe0, 0xd4, 0x05
};
#endif
    UINT32 count = 1024U;
    CHAR l_AesKey[64] = {0};

    g_CryptoPbkdf_PbkdfOperation(l_PwdBuf, 18, l_SaltBuf, 22, count, len, l_AesKey);
 
    printf("Crypto verify output:\n");
    g_Debug_Printf(l_AesKey, 60);
}


UINT32 g_CryptoBase64_enc(const void *data, int data_len, char *buffer)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new(BIO_s_mem());

    printf("Do base64 encode\n");
    g_Debug_Printf(data, data_len);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, data_len);
    BIO_ctrl(bio, BIO_CTRL_FLUSH, 0, NULL);

    BUF_MEM *bptr = NULL;
    BIO_get_mem_ptr(bio, &bptr);

    size_t slen = bptr->length;
    memcpy(buffer, bptr->data, slen);
    buffer[slen] = '\0';

    BIO_free_all(bio);
    return slen;
}








UINT32 g_CryptoBase64_dec(unsigned char *input, int length, char* output)
{
  BIO *b64, *bmem;
  UINT32 l_RetLen = 0U;

  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new_mem_buf(input, length);
  bmem = BIO_push(b64, bmem);

  l_RetLen = BIO_read(bmem, output, length);
  output[length] = '\0';

  BIO_free_all(bmem);

  return l_RetLen;
}









/**
 * @}
 */
