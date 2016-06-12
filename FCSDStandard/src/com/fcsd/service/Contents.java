/**
 *------------------------------------------------------------------------------
 *  Project name    : smartpen
 *                      - Java Card Open Platform applet -
 *
 *  Platform        :  Java virtual machine
 *  Language        :  java 1.3.0-C
 *  Devl tool       :  Borland (c) JBuilder 4.0
 *
 *  Original author : Menghongwen@gmail.com 
 *  Date            : 2004, 11
 *------------------------------------------------------------------------------
 */

package com.fcsd.service;

public class Contents
{

    // ----------- CLA Byte ------------------------------
    final static byte CUP_CLA = ( byte ) 0x80;

    // ----------- INS Byte ------------------------------
    final static byte INS_CREATEFS = ( byte ) 0xE2;

    final static byte INS_VERIFY = ( byte ) 0x42;

    final static byte INS_CHALLENGE = ( byte ) 0x48;


    // transaction
    final static byte INS_GETBAL = ( byte ) 0x5C;

    final static byte INS_INITTRANS = ( byte ) 0x50;

    final static byte INS_PURCHASE = ( byte ) 0x54;

    final static byte INS_LOAD = ( byte ) 0x52;

    final static byte APP_BLOCK = ( byte ) 0x1E;

    final static byte APP_UNBLOCK = ( byte ) 0x18;

    final static byte CARD_BLOCK = ( byte ) 0x16;

    final static byte GET_TRANS_PROOF = ( byte ) 0x5A;

    // ----------- SW Code ------------------------------
    final static short SW_E_INTERNAL = ( short ) 0x6581;

    final static short SW_E_FTYPE = ( short ) 0x6a02;

    final static short SW_E_PINBLKED = ( short ) 0x6a83;

    final static short SW_E_OPFTYPE = ( short ) 0x6981;

    final static short SW_E_REFDATA = ( short ) 0x6a88;

    final static short SW_E_SMDATA = ( short ) 0x6988;

    final static short SW_E_APPBLK = ( short ) 0x6A81;

    final static short SW_E_UPCARD = ( short ) 0x6A74;

    final static short SW_E_UPCARDSIO = ( short ) 0x6A78;
    
    final static short SW_E_AUTH_FAIL = (short) 0x6300;
    
    final static short SW_S_MORE_DATA = (short) 0x6310;

    //----------- constants ----------------------------
    final static short CONST_RetryTimes = ( short ) 3;
    
    //Util.arraycopy支持的最大长度
    final static short MAX_COPYLEN = (short)500;

    //安全通道加密数据的最大长度
    final static short MAX_DECRYPTLEN = (short)240;
    
    //相应数据的最大长度
    final static short MAX_RESLEN = (short)240;
}