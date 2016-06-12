/*****************************************************************
 * 版权所有 (C) 2013年 - 2020年, HED
 * 文  件  名：FCSDInterface.java
 * 版        本：V1.00
 * 创  建  人：罗弘谞
 * 创建日期：2013-7-4
 * 描        述：此文件用于声明FCSD类可以对外提供的方法。
 * 修  改  人：
 * 修改日期：
 * 修改描述：
 *****************************************************************/

package com.fcsd.service;

import javacard.framework.Shareable;


/**
 * 类        名：FCSDService<br>
 * 创  建  人：罗弘谞<br>
 * 创建日期：2013-07-04<br>
 * 功能描述：声明FCSD类对金融应用提供的服务。<br>
 * 修  改  人：<br>
 * 修改日期：<br>
 * 修改描述：<br>
 */
public interface FCSDService extends Shareable {

	/**
	 * 方  法  名：sign<br>
	 * 功能描述：该方法用于为金融应用提供签名服务，使用参数中的密钥版本来指定要使用哪个非对称密钥来完成签名的操作。<br>
	 * 创建日期：2013-07-04<br>
	 * 修  改  人：<br>
	 * 修改日期：<br>
	 * 修改描述：<br>
	 * @param keyRef，用于标识使用的密钥的版本号和ID；
	 * @param buffer 输入待签名数据所在的buffer；
	 * @param sOffset 输入待签名数据在buffer中的起始偏移；
	 * @param sLength 输入签名数据的长度；
	 * @param sigBuffer 签名后的结果存放的数组；
	 * @param destOffet 签名后的结果在sigBuffer中存放的起始位置。
	 * @return short型，返回签名结果数据的长度。
	 */
	public short sign(short keyRef, byte[] buffer, short sOffset, short sLength , byte[] sigBuffer, short destOffet);
	
	/**
	 * 方  法  名：verify<br>
	 * 功能描述：该方法用于为金融应用提供签名验证的服务，使用参数中的密钥版本来指定要使用哪个非对称密钥来完成签名验证的操作。<br>
	 * 创建日期：2013-07-04<br>
	 * 修  改  人：<br>
	 * 修改日期：<br>
	 * 修改描述：<br>
	 * @param keyRef，用于标识使用的密钥的版本号和ID；
	 * @param buffer 输入待签名数据所在的buffer；
	 * @param sOffset 输入待签名数据在buffer中的起始偏移；
	 * @param sLength 输入签名数据的长度；
	 * @param sigBuffer 签名后的结果存放的数组；
	 * @param sigOffet 签名结果在sigBuffer中存放的起始位置；
	 * @param sigLength 签名数据的字节长度。
	 * @return boolean型，返回签名验证结果。
	 */
	public boolean verify(short keyRef, byte[] buffer, short sOffset, short sLength, byte[] sigBuffer, short sigOffset, short sigLength);
	
	/**
	 * 方  法  名：encryption<br>
	 * 功能描述：该方法用于为金融应用提供加密服务，使用参数中的密钥版本来指定要使用哪个非对称密钥来完成加密的操作。<br>
	 * 创建日期：2013-07-04<br>
	 * 修  改  人：<br>
	 * 修改日期：<br>
	 * 修改描述：<br>
	 * @param keyRef，用于标识使用的密钥的版本号和ID；
	 * @param buffer 输入待加密数据所在的buffer；
	 * @param sOffset 输入待加密数据在buffer中的起始偏移；
	 * @param sLength 输入加密数据的长度；
	 * @param encBuffer 加密后的结果存放的数组；
	 * @param destOffet 加密后的结果在encBuffer中存放的起始位置；
	 * @return short型，返回加密结果数据的长度。
	 */
	public short encrypt(short keyRef, byte[] buffer, short sOffset, short sLength, byte[] encBuffer, short destOffet);
	
	/**
	 * 方  法  名：decryption<br>
	 * 功能描述：该方法用于为金融应用提供解密服务，使用参数中的密钥版本来指定要使用哪个非对称密钥来完成解密的操作。<br>
	 * 创建日期：2013-07-04<br>
	 * 修  改  人：<br>
	 * 修改日期：<br>
	 * 修改描述：<br>
	 * @param keyRef，用于标识使用的密钥的版本号和ID；
	 * @param buffer 输入待签名数据所在的buffer；
	 * @param sOffset 输入待签名数据在buffer中的起始偏移；
	 * @param sLength 输入签名数据的长度；
	 * @param dekBuffer 解密后的结果存放的数组；
	 * @param destOffet 解密后的结果在dekBuffer中存放的起始位置；
	 * @return short型，返回解密操作的结果长度。
	 */
	public short decrypt(short keyRef, byte[] buffer, short sOffset, short sLength, byte[] dekBuffer, short destOffet);
	
	/**
	 * 方  法   名：getCert<br>
	 * 功能描述：该方法用于为应用读取公钥证书。<br>
	 * 创建日期：2013-8-7<br>
	 * 修  改   人：<br>
	 * 修改日期：<br>
	 * 修改描述：<br>
	 * @param certTag 用于标识使用的证书；
	 * @param certBuff 输出证书数据的buff；
	 * @param buffOffset certBuff的起始偏移；
	 * @param sOffset 读证书数据的起始偏移；
	 * @param sLength 读证书数据的长度
	 * @return 返回证书的剩余长度。
	 */
	public short getCert(byte certTag, byte[] certBuff, short buffOffset,  short sOffset, short sLength);
}
