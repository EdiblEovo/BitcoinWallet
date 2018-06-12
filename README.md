# BitcoinWallet

## Overview

CLA = 0x80

To access different functions, use INS as below:

getID : 0x81

getName : 0x82

mine : 0x83

generateWallet : 0x84

## functions

### getID

Return 10-byte student ID number indicated by ASCII code.

### getName

Return the student name indicated by GB2312 code.

### mine

Simple mining simulation using Data as header and P1 as difficulty.
Used SHA1 for hashing.
Return the valid hash code and nonce data if succeed.
Return format: {hashcode , 0x00 , nonce data}

### generateWallet

Simple encryption for Data.
First SHA1, then RIPEMD160, then base58check.
Return the encrypted data.
