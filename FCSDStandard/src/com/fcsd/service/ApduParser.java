/**
 * Title:        apdu
 * Description:
 * Copyright:    Copyright (c) 2004
 * Company:      Gemplus Goldpac Co., Limited
 *
 * @author       Meng Hongwen<alfredmeng@eastday.com>
 * @version 1.0
 */

package com.fcsd.service;

public class ApduParser {

	public byte cla, ins, p1, p2;

	public short lc, le;

	public boolean APDUContainData() {

		switch (ins) {
		case (byte) 0xE2:// STORE DATA命令，写入或更新数据（PAMID，证书）
		case (byte) 0xCA:// GET DATA命令，读取pamid或者证书
		case (byte) 0x42:// 产生公私钥
		case (byte) 0x48:// 数字签名
		case (byte) 0xE6:// load指令
		case (byte) 0x50:// 外部认证
		case (byte) 0x43:// 重置FCSD
		case (byte) 0x82:// 外部认证
		case (byte) 0xC0:// get response
			return true;
		}
		return false;
	}

	/**
	 * rest method
	 */
	public void clear() {
		cla = (byte) 0x00;
		ins = (byte) 0x00;
		p1 = (byte) 0x00;
		p2 = (byte) 0x00;
	}
}