/**
 * 
 */
package cn.z.EDEP;

import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.ISO7816;
import javacard.framework.APDU;
import javacard.framework.JCSystem;

/**
 * @author daor
 *
 */
public class EPMain extends Applet {
	
	/** 临时数据缓存区 */
	private byte[] rambytes = null;
	/** 数据元缓存区*/
	private byte[] CARD_DATA_BUF = null;
	
	/** 算法标志 DLK，用 来 标 识 圈 存 交 易 的 加 密 算法 */
	private static final short CARD_DATA_OFF_ALG_DLK = (short)0x00;
	private static final short CARD_DATA_LEN_ALG_X = (short)0x01;
	
	/** 算法标识DPK，用来标识消费和取现交易的加密算法*/
	private static final  short CARD_DATA_OFF_ALG_DPK = (short)(CARD_DATA_OFF_ALG_DLK + CARD_DATA_LEN_ALG_X);
	
	/** 算法标识DTK，用来标识在交易中计算TAC使用的加密算法 */
	private static final short CARD_DATA_OFF_ALG_DTK= (short)(CARD_DATA_OFF_ALG_DPK + CARD_DATA_LEN_ALG_X);
	
	/** 算法标识DUK，用来标识在修改透支限额交易中使用的加密算法 */
	private static final short CARD_DATA_OFF_ALG_DUK = (short)(CARD_DATA_OFF_ALG_DTK + CARD_DATA_LEN_ALG_X);;
	
	/** 算法标识DULK，用来标识在圈提交易中使用的加密算法 */
	private static final short CARD_DATA_OFF_ALG_DULK = (short)(CARD_DATA_OFF_ALG_DUK + CARD_DATA_LEN_ALG_X);;

	/** 应用有效期，该日期后卡片应用终止 */
	private static final short CARD_DATA_OFF_DATE_APPEND = (short)(CARD_DATA_OFF_ALG_DULK + CARD_DATA_LEN_ALG_X);
	private static final short CARD_DATA_LEN_DATE_X = (short)0x0006;

	/** 应用标识符AID，用于标识一个应用，并符合GB/T 16649.5 */
	private static final short CARD_DATA_OFF_AID = (short)(CARD_DATA_OFF_DATE_APPEND +CARD_DATA_LEN_DATE_X);
	private static final short CARD_DATA_OFF_AID_LEN = (short)(CARD_DATA_OFF_DATE_APPEND +CARD_DATA_LEN_DATE_X);
	private static final short CARD_DATA_OFF_AID_VALUE = (short)(CARD_DATA_OFF_AID_LEN +1);
	private static final short CARD_DATA_LEN_AID = (short)0x0011;

	/** 应用序列号 Series number，发卡方分配的一个数字  */
	private static final short CARD_DATA_OFF_SERNUM = (short)(CARD_DATA_OFF_AID + CARD_DATA_LEN_AID);
	private static final short CARD_DATA_LEN_SERNUM = (short)0x0000A;
	
	/** 应用启用日期,指示应用生效日期 */
	private static final short CARD_DATA_OFF_DATE_APPSTART =  (short)(CARD_DATA_OFF_SERNUM + CARD_DATA_LEN_SERNUM);
	
	/** 应用类型标识，IC卡支持的表示卡支持的应用类型标识，ED或者EP，01--ED，02-EP，03--ED&EP  */
	private static final short CARD_DATA_OFF_FLAG_APPTYPE = (short)(CARD_DATA_OFF_DATE_APPSTART + CARD_DATA_LEN_DATE_X);
	private static final short CARD_DATA_LEN_FLAG_X =(short)0x01;
	private static final short CARD_DATA_VALUE_FLAG_APPTYPE_ED = (byte)0x01;
	private static final short CARD_DATA_VALUE_FLAG_APPTYPE_EP = (byte)0x02;

	
	/** 应用版本号，表示 IC 卡当前使用的应用版本的一个数字。  */
	private static final short CARD_DATA_OFF_VER_ICAPP = (short)(CARD_DATA_OFF_FLAG_APPTYPE + CARD_DATA_LEN_FLAG_X);
	private static final short CARD_DATA_LEN_VER_X =(short)0x01; 
	
	/** 发卡行应用版本，表示发卡方当前使用的应用版本的一个数字 */
	private static final short CARD_DATA_OFF_VER_IBAPP = (short)(CARD_DATA_OFF_VER_ICAPP + CARD_DATA_LEN_VER_X);
	
	/** 本行职工标识，用来表示持卡人是否是银行职员的一个标识，该标识可以用来获取某种优惠 */
	private static final short CARD_DATA_OFF_FLAG_STAFF = (short)(CARD_DATA_OFF_VER_IBAPP + CARD_DATA_LEN_VER_X);
	
	/** 卡类型标识,00--个人化卡，10--单位卡 */
	private static final short CARD_DATA_OFF_FLAG_ICTYPE = (short)(CARD_DATA_OFF_FLAG_STAFF + CARD_DATA_LEN_FLAG_X);
	private static final byte  CARD_DATA_VALUE_FLAG_ICTYPE_PERSON = (byte)0x00;
	private static final byte  CARD_DATA_VALUE_FLAG_ICTYPE_FIRM = (byte)0x10;
	
	/** 持卡人证件号码，用来标识持卡人 */
	private static final short CARD_DATA_OFF_CERTIFICATE_ID = (short)(CARD_DATA_OFF_FLAG_ICTYPE + CARD_DATA_LEN_FLAG_X);
	private static final short CARD_DATA_LEN_CERTIFICATE_ID = (short)0x20;
	
	/** 制卡人证件类型，用来标识证件类型 */
	private static final short CARD_DATA_OFF_FLAG_CERTIFICATE_TYPE= (short)(CARD_DATA_OFF_CERTIFICATE_ID + CARD_DATA_LEN_CERTIFICATE_ID);;
	private static final byte CARD_DATA_VALUE_SHENFENZHENG = (byte)0x00;
	private static final byte CARD_DATA_VALUE_JUNGUANHENG = (byte)0x01;
	private static final byte CARD_DATA_VALUE_PASSPORT = (byte)0x02;
	private static final byte CARD_DATA_VALUE_RUJINGZHENG = (byte)0x03;
	private static final byte CARD_DATA_VALUE_LINSHISHENFENZHENG = (byte)0x04;
	private static final byte CARD_DATA_VALUE_OTHER = (byte)0x05;

	
	/** 持卡人姓名，根据 GB/T 17552 格式，标识持卡人姓名  */
	private static final short CARD_DATA_OFF_NAME_ICOWNER = (short)(CARD_DATA_OFF_FLAG_CERTIFICATE_TYPE + CARD_DATA_LEN_FLAG_X);
	private static final short CARD_DATA_LEN_NAME_ICOWNER = (short)0x14;
	
	/** ED余额， IC 卡中 ED 的当前余额。这个ED 余额是卡上实际余额和透支限额之和。*/
	private static final short CARD_DATA_OFF_EDBLANCE = (short)(CARD_DATA_OFF_NAME_ICOWNER + CARD_DATA_LEN_NAME_ICOWNER);
	private static final short CARD_DATA_LEN_EDBLANCE = (short)0x04;
	
	/**ED 脱机交易计数器  */
	private static final short CARD_DATA_OFF_COUNTER_ED_TRDE_OFFLINE = (short)(CARD_DATA_OFF_EDBLANCE + CARD_DATA_LEN_EDBLANCE);
	private static final short CARD_DATA_LEN_COUNTER_X = (short)0x02;
	
	/** ED联机交易计数器，IC卡中的一个计数器，每发生一次 ED 圈存、圈提或修改透支限额交易时就增加。该计数器和主机同步，并且可以在过程密钥的产生中使用。  */
	private static final short CARD_DATA_OFF_COUNTER_ED_TRDE_ONLINE = (short)(CARD_DATA_OFF_COUNTER_ED_TRDE_OFFLINE + CARD_DATA_LEN_COUNTER_X);
	
	/** EP余额，IC卡中EP的当前余额 */
	private static final short CARD_DATA_OFF_EPBLACE = (short)(CARD_DATA_OFF_COUNTER_ED_TRDE_ONLINE + CARD_DATA_LEN_COUNTER_X);
	private static final short CARD_DATA_LEN_EPBLACE =  (short)0x03;
	
	/** ED脱机交易计数器，IC 卡中的一个计数器，每当EP消费交易发生就增加。 */
	private static final short CARD_DATA_OFF_COUNTER_EP_TRDE_OFFLINE = (short)(CARD_DATA_OFF_EPBLACE + CARD_DATA_LEN_EPBLACE);
	
	/** EP联机交易计数器，IC卡中的一个计数器，每次发生EP圈存交易时就增加。该计数器和主机同步，并且可以在过程密钥的产生中使用。*/
	private static final short CARD_DATA_OFF_COUNTER_EP_TRDE_ONLINE = (short)(CARD_DATA_OFF_COUNTER_EP_TRDE_OFFLINE + CARD_DATA_LEN_COUNTER_X);

	/** 发卡方唯一标识，用来唯一标识发卡方的一个数字 */
	private static final short CARD_DATA_OFF_ISSUER_ORGID = (short)(CARD_DATA_OFF_COUNTER_EP_TRDE_ONLINE + CARD_DATA_LEN_COUNTER_X);
	private static final short CARD_DATA_LEN_ISSUER_ORGID = (short)0x08;

	/** 发卡方自定义FCI数据,发卡方在其自己终端上用于特殊处理的自定义数据 */
	private static final short CARD_DATA_OFF_FCIDATA_ONLYFORISSUER = (short)(CARD_DATA_OFF_ISSUER_ORGID + CARD_DATA_LEN_ISSUER_ORGID);
	private static final short CARD_DATA_LENF_FCIDATA_ONLYFORISSUER = (short)0x02;

	/** 密钥索引，为了标识一个密钥版本中的密钥索引号二分配的一个数字  */
	private static final short CARD_DATA_OFF_KEYINDEX = (short)(CARD_DATA_OFF_FCIDATA_ONLYFORISSUER + CARD_DATA_LENF_FCIDATA_ONLYFORISSUER);
	private static final short CARD_DATA_LEN_KEYINDEX = (short)0x01;

	/** 密钥版本号DLK，用来标识圈存交易的密钥版本  */
	private static final short CARD_DATA_OFF_KEYVER_DLK = (short)(CARD_DATA_OFF_KEYINDEX + CARD_DATA_LEN_KEYINDEX);
	private static final short CARD_DATA_LEN_KEYVER_X = (short)0x01; 

	/**  密钥版本号DPK，用来标识消费的密钥版本*/
	private static final short CARD_DATA_OFF_KEYVER_DPK = (short)(CARD_DATA_OFF_KEYVER_DLK + CARD_DATA_LEN_KEYVER_X);
	
	/** 密钥版本号DTK，用来标识计算TAC的密钥版本  */
	private static final short CARD_DATA_OFF_KEYVER_DTK = (short)(CARD_DATA_OFF_KEYVER_DPK + CARD_DATA_LEN_KEYVER_X);

	/** 密钥版本号DUK，用来唯一标识一个修改透支限额交易的密钥版本。  */
	private static final short CARD_DATA_OFF_KEYVER_DUK = (short)(CARD_DATA_OFF_KEYVER_DTK + CARD_DATA_LEN_KEYVER_X);

	/** 密钥版本号DULK，用来唯一标识一个圈提交易的密钥版本。  */
	private static final short CARD_DATA_OFF_KEYVER_DULK = (short)(CARD_DATA_OFF_KEYVER_DUK + CARD_DATA_LEN_KEYVER_X);

	/** 透支限额，发卡方给持卡人最大的透支额度 */
	private static final short CARD_DATA_OFF_LIMIT_OVERDRAW = (short)(CARD_DATA_OFF_KEYVER_DULK + CARD_DATA_LEN_KEYVER_X);
	private static final short CARD_DATA_LEN_LIMIT_OVERDRAW = (short)0x03;  

	/** PIN尝试计数器，用来记录剩余PIN尝试次数  */
	private static final short CARD_DATA_OFF_PIN_COUNTER = (short)(CARD_DATA_OFF_LIMIT_OVERDRAW + CARD_DATA_LEN_LIMIT_OVERDRAW );
	private static final short CARD_DATA_LEN_PIN_COUNTER = (short)0x01; 

	/** PIN尝试上线，发卡方给定的一个应用中允许PIN连续错误的最大次数。 */
	private static final short CARD_DATA_OFF_UPLIMIT_PINCOUNTER = (short)(CARD_DATA_OFF_PIN_COUNTER + CARD_DATA_LEN_PIN_COUNTER );
	private static final short CARD_DATA_LEN_UPLIMIT_PINCOUNTER = (short)0x01; 
	private static final byte CARD_DATA_VALUE_UPLIMIT_PINCOUNTER_INIT = (byte)0x0F; 

	/** 伪随机数，IC 卡随机产生的一个数字 */
	private static final short CARD_DATA_OFF_FAKERANDOM = (short)(CARD_DATA_OFF_UPLIMIT_PINCOUNTER + CARD_DATA_LEN_UPLIMIT_PINCOUNTER );
	private static final short CARD_DATA_LEN_FAKERANDOM = (short)0x04;

	/**PIN参考值，IC 卡中存放的用来与持卡人输入的个人识别码的值进行比较的值,2~6。  */
	private static final short CARD_DATA_OFF_PIN = (short)(CARD_DATA_OFF_FAKERANDOM + CARD_DATA_LEN_FAKERANDOM ); 
	private static final short CARD_DATA_OFF_PIN_LNE = CARD_DATA_OFF_PIN; 
	private static final short CARD_DATA_OFF_PIN_VALUE = (short)(CARD_DATA_OFF_PIN + 1 );; 
	private static final short CARD_DATA_LEN_PIN = (short)0x06;

	/** 交易类型标识，用于标识持卡人选择的交易类型（例如：圈存、圈提及消费等）而分配的一个值。 */
	private static final short CARD_DATA_OFF_FLAG_TRDETYPE = (short)(CARD_DATA_OFF_PIN + CARD_DATA_LEN_PIN );
	
	/** 数据元缓存区总长度*/
	private static final short CARD_DATA_BUF_LEN = (short)(CARD_DATA_OFF_FLAG_TRDETYPE + CARD_DATA_LEN_FLAG_X);
	
	/** 密钥数据存储区*/
	private byte[] KEY_DATA_BUF = null;
	
	/** 消费密钥DPK，用于消费/取现交易的密钥*/
	private static final short KEY_DATA_OFF_KEY_DPK = (short)0x00;
	private static final short KEY_DATA_LEN_KEY_X = (short)0x10;
	
	/** 圈存密钥DLK，用于圈存交易的密钥*/
	private static final short KEY_DATA_OFF_KEY_DLK = (short)(KEY_DATA_OFF_KEY_DPK + KEY_DATA_LEN_KEY_X);

	/** TAC子密钥DTK*/
	private static final short KEY_DATA_OFF_KEY_DTK = (short)(KEY_DATA_OFF_KEY_DLK + KEY_DATA_LEN_KEY_X);
	
	/** PIN 解锁子密钥DPUK*/
	private static final short KEY_DATA_OFF_KEY_DPUK = (short)(KEY_DATA_OFF_KEY_DTK + KEY_DATA_LEN_KEY_X);
	
	/** PIN 重装子密钥（DRPK）*/
	private static final short KEY_DATA_OFF_KEY_DRPK = (short)(KEY_DATA_OFF_KEY_DPUK + KEY_DATA_LEN_KEY_X);
	
	/** 应用主控子密钥（DAMK）*/
	private static final short KEY_DATA_OFF_KEY_DAMK = (short)(KEY_DATA_OFF_KEY_DRPK + KEY_DATA_LEN_KEY_X);

	/** 圈提子密钥（DULK）*/
	private static final short KEY_DATA_OFF_KEY_DULK = (short)(KEY_DATA_OFF_KEY_DAMK + KEY_DATA_LEN_KEY_X);
	
	/** 修改透支限额子密钥（DUK）*/
	private static final short KEY_DATA_OFF_KEY_DUK = (short)(KEY_DATA_OFF_KEY_DULK + KEY_DATA_LEN_KEY_X);

	/** 密钥存储区总长度*/
	private static final short KEY_DATA_LEN = (short)(KEY_DATA_OFF_KEY_DUK + KEY_DATA_LEN_KEY_X);

	/** 文件存储区*/
	private byte[] FILE_BUF = null;
	private static final byte FILE_TYPE_BINARY = (byte)0x00;
	private static final byte FILE_TYPE_RECORD = (byte)0x01;
	private static final byte FILE_TYPE_LOOPRECORD = (byte)0x02;
	private static final byte FILE_PRI_READ_FREE = (byte)0x00;
	private static final byte FILE_PRI_READ_PIN = (byte)0x40;
	private static final byte FILE_PRI_READ_SECURITE = (byte)0x80;
	private static final byte FILE_PRI_WRITE_FREE = (byte)0x00;
	private static final byte FILE_PRI_WRITE_PIN = (byte)0x40;
	private static final byte FILE_PRI_WRITE_SECURITE = (byte)0x80;
	private static final byte FILE_PRI_WRITE_NONE = (byte)0xFF;


	
	/** ED和 EP应用的公共应用基本文件*/
	private static final short FILE_OFF_SFI15 = (short)0x00;
	private static final byte FILE_TYPE_SFI15 = FILE_TYPE_BINARY;
	private static final short FILE_LEN_SFI15 = (short)0x001E;
	private static final byte FILE_PRI_READ_SFI15 = FILE_PRI_READ_FREE;
	private static final byte FILE_PRI_WRITE_SFI15 = FILE_PRI_WRITE_SECURITE;
	
	/** ED和EP应用的持卡人基本文件*/
	private static final short FILE_OFF_SFI16 = (short)(FILE_OFF_SFI15 + FILE_LEN_SFI15);
	private static final byte FILE_TYPE_SFI16 = FILE_TYPE_BINARY;
	private static final short FILE_LEN_SFI16 = (short)0x0037;
	private static final byte FILE_PRI_READ_SFI16 = FILE_PRI_READ_FREE;
	private static final byte FILE_PRI_WRITE_SFI16 = FILE_PRI_WRITE_SECURITE;
	
	/** IC 卡交易明细文件*/
	private static final short FILE_OFF_SFI19 = (short)(FILE_OFF_SFI16 + FILE_LEN_SFI16);
	private static final byte FILE_TYPE_SFI19 = FILE_TYPE_LOOPRECORD;
	private static final byte FILE_LNE_RECODESUM_SFI19 = (byte)0x0A;
	private static final byte FILE_LEN_RECODELEN_SFI19 = (byte)0x18;
	private static final short FILE_LEN_SFI19 = (short)(FILE_LNE_RECODESUM_SFI19 * FILE_LEN_RECODELEN_SFI19);
	private static final byte FILE_PRI_READ_SFI19 = FILE_PRI_READ_PIN;
	private static final byte FILE_PRI_WRITE_SFI19 = FILE_PRI_WRITE_NONE;
	
	/** 文件存储区从长度*/
	private short FILE_BUF_LEN = (short)(FILE_OFF_SFI19 + FILE_LEN_SFI19);
	
	private EPMain() {	
		CARD_DATA_BUF = new byte[CARD_DATA_BUF_LEN];
		KEY_DATA_BUF =new byte[KEY_DATA_LEN];
		FILE_BUF = new byte[FILE_BUF_LEN];
		rambytes = JCSystem.makeTransientByteArray((short)0x0100, JCSystem.CLEAR_ON_RESET);
		init();
	}
	private void init(){
		
	}
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new cn.z.EDEP.EPMain().register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}

		byte[] buf = apdu.getBuffer();
		byte INS =(byte) buf[ISO7816.OFFSET_INS];
		byte P1 = (byte)buf[ISO7816.OFFSET_P1];
		byte P2 = (byte)buf[ISO7816.OFFSET_P2];
		switch (INS) {
		//卡片基础指令
		case (byte)0x1E://APPLICATION BLOCK
			break;
		case (byte)0x18://APPLICATION UNBLOCK
			break;
		case (byte)0x16://CARD BLOCK
			break;
		case (byte)0x82://EXTERNAL AUTHENTICATION
			break;
		case (byte)0x84://GET CHALLENGE
			break;
		case (byte)0xC0://GET RESPONSE
			break;
		case (byte)0x88://INTERNAL AUTHENTICATION
			break;
		case (byte)0x24://PIN UNBLOCK
			break;
		case (byte)0xB0://READ BINARY
			break;
		case (byte)0xB2://READ RECORD
			break;
		case (byte)0xA4://SELECT
			break;
		case (byte)0xD6://UPDATE BINARY
			break;
		case (byte)0xDC://UPDATE RECORD
			break;
		case (byte)0x20://VERIFY
			break;
		
		/** 以下是钱包指令**/
		case (byte) 0x5E://修改个人识别码,change PIN
			if(((byte)0x01 == P1) && ((byte)0x00 ==  P2)){
				//
			}else if(((byte)0x00 == P1) && ((byte)0x00 ==  P2)){
				//RELOAD PIN
			}else{
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				break;
			}
			break;
		case (byte) 0x52://圈存，credit for load
			if(((byte)0x00 == P1) && ((byte)0x00 ==  P2)){
				//
			}else{
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				break;
			}
			break;
		case (byte) 0x54://消费/取现/圈提
			if(((byte)0x01 == P1) && ((byte)0x00 ==  P2)){
				//消费/取现
			}else if(((byte)0x01 == P1) && ((byte)0x00 ==  P2)){
				//圈提
			}else{
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				break;
			}
			break;
		case (byte) 0x5C://读余额
			if(((byte)0x00 == P1) && ((byte)0x0F ==  (byte)(P2 | (byte)0x0F))){
				//get balance
			}else{
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				break;
			}
			break;
		case (byte) 0x5A://取交易认证
			if((byte)0x00 == P1){
				//GET TRANSACTION PROVE
			}else{
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				break;
			}
			break;
		case (byte) 0x50://交易初始化
			if(((byte)0x02 == P1) && ((byte)0x01 ==  P2)){
				//INITIALIZE FOR CASH WITHDRAW
			}else if(((byte)0x00 == P1) && ((byte)0x0F ==  (byte)(P2 | (byte)0x0F))){
				//INITIALIZE FOR LOAD
			}else if(((byte)0x01 == P1) && ((byte)0x0F ==  (byte)(P2 | (byte)0x0F))){
				//INITIALIZE FOR PURCHASE
			}else if(((byte)0x05 == P1) && ((byte)0x01 ==  P2)){
				//INITIALIZE FOR UNLOAD
			}else if(((byte)0x04 == P1) && ((byte)0x00 ==  P2)){
				//INITIALIZE FOR UPDATE
			}else{
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				break;
			}
			break;
		case (byte) 0x58://修改透支限额
			if(((byte)0x00 == P1) && ((byte)0x00 ==  P2)){
				//UPDATE OVERDRAW LIMIT
			}else{
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				break;
			}
			break;
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}