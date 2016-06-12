package com.fcsd.service;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * 存储证书数据
 * @author Administrator
 *
 */
public class Cert {
	 public byte[] data = new byte[1024];//四个证书53、54、55、56
	 public short certDataLen = 0;//是个证书的实际长度
	 public short totalLen =0;//证书总长度
	 public boolean writeFlag = false;//证书写入标记
	 public short readSet=0;//证书读取标志
	 public boolean decryFlag=false;//证书解密标识
	 public boolean finashFlag=false;;//证书写完标示
	 
	 public boolean Copy(Cert src){
		 Util.arrayCopy(src.data , (short)0, this.data, (short)0, (short)1024);
		 this.certDataLen = src.certDataLen;
		 this.totalLen = src.totalLen;
		 this.writeFlag = src.writeFlag;
		 this.readSet = src.readSet;
		 this.decryFlag = src.decryFlag;
		 this.finashFlag = src.finashFlag;
		 return true;
	 }
	 
	 /**
	  * reset method
	  */
	 public void clear(){
		 Util.arrayFillNonAtomic(data, (short)0, (short)data.length, (byte)0x00);
		 certDataLen = 0;
		 writeFlag = false;
		 readSet = 0;
		 decryFlag = false;
	 }
	 
	 /**
	  * 写入第一条证书数据
	  * @param buf
	  * @param len
	  */
	 public void writeFirstData(byte[] buf,short len,short totalLen){
		 
		 Util.arrayCopy(buf, (short)(buf[4]&0xFF - len +5), data, ( short ) 0, len);
		 
		 writeFlag = true;
		 finashFlag = false;
		 certDataLen = len;
		 this.totalLen = totalLen;
	 }
	 
	 /**
	  * 写入剩余证书数据
	  * @param buf
	  * @param len
	  */
	 public void writeOtherData(byte[] buf){
		 short len = ( short ) (buf[4] & 0xFF);
		 if(writeFlag){
			 Util.arrayCopy(buf, ( short ) 5, data, ( short ) certDataLen, ( short ) len);
			 certDataLen += len;
			 if((buf[ISO7816.OFFSET_P1] & 0x80) == 0x80){
				 finashFlag = true;
				 writeFlag = false;
				 if(certDataLen != totalLen){
					 ISOException.throwIt(ISO7816.SW_CORRECT_LENGTH_00);
				 }
			 }
		 }		
	 }
	 
	 public Cert resetWFlag(Cert cert){
		 cert.writeFlag = false;
		 return this;
	 }
}
