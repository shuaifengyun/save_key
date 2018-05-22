SaveKey
    dispatch key on line This package include a solution to dispatch keys on line which base on TEE. 
because this is a simple demo, so about algroithm which in this demo is simple, you can develop or 
replace some other algorithm by yourself.

Usage: 
1. apply patch in package to integrate this TA and CA into OP-TEE 
2. build OP-TEE 3. run CA command 
    A. send message to OP-TEE and save them by secure storage 
        CA command: saveKey save 
    B. Get key which is saved by OP-TEE(value of key will display in OP-TEE) 
        CA command: saveKey get

Offline tool: 
    offline tool is used to generate cipher package data, which will be used by CA command. you can 
change salt data and password data to generate different key package, and variable of "g_Message" in 
CA, then you can get different key value. About more info, you can see source code of this demo
