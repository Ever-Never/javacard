
package com.fcsd.service;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.Util;
import javacard.security.KeyPair;
import javacard.security.PrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;



public class Main extends Applet implements FCSDService
{

    private static boolean CERTENCRYPTFLAG = false;// 读取的证书是否使用加密保护

    private ApduParser apduin = new ApduParser();

    private Cert cert53 = new Cert();// 四个证书53、54、55、56

    private Cert cert54 = new Cert();// 四个证书53、54、55、56

    private Cert cert55 = new Cert();// 四个证书53、54、55、56

    private Cert cert56 = new Cert();// 四个证书53、54、55、56

    byte caseValue;

    short offset;

    short flag;

    short echoOffset;

    short prsflag;

    short certDataLen;// 预计写入证书的长度

    private byte[] pamidset = new byte[32];// pamid

    private byte[] ridset = new byte[32];

    private byte[] scset = new byte[32];

    byte[] tempPub = new byte[5];

    Cipher rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, true); /* 定义RSA算法对象 */

    Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, true);

    KeyPair keyPair7A;

    KeyPair keyPair7B;

    KeyPair keyPair7C;

    private Cert tempCert = new Cert();// 读取证书时的临时缓存
    private Cert ptempCert = new Cert();// 读取证书时的临时缓存,明文


    private boolean extAuthFlg = false;// 外部认证标示 false为未验证，true为已验证

    public SecureChannel secureChannel;

    // ------------------------
    byte[] signBuffer2 = new byte[128];

    boolean flagD=false;
    
    byte[] signData= new byte[128];
    
    byte[] signed=new byte[128];
    // ------------------------
    public static void install(byte[] bArray, short bOffset, byte bLength)
    {

        Main main = new Main();

        main.register(bArray, ( short ) (bOffset + 1), bArray[bOffset]);
    }

    public void process(APDU apdu)
    {
        byte[] buffer = apdu.getBuffer();
        buffer[0] = ( byte ) (buffer[0] & 0xFC);
        // 选择应用
        if (selectingApplet())
        {
            extAuthFlg = false;
            secureChannel = GPSystem.getSecureChannel();
            secureChannel.resetSecurity();
            return;
        }

        // 指令的安全性管理
        byte[] buf = apduSecurityManager(apdu);
        if (buf == null)
        {
            return;
        }

        // 证书的初始化管理
        certInitManager();

        // 进行业务处理
        switch (buf[ISO7816.OFFSET_INS])
        {
            case ( byte ) 0xCA:
                getData(buf[ISO7816.OFFSET_P1], apdu);
                break;
            // write in
            case ( byte ) 0xE2:

                if (apduin.lc > 0)
                {
                    if (buf[5] == ( byte ) 0x00 && buf[6] == ( byte ) 0x70)
                    {
                        // 写入每种证书第一条之前重置写入标志为0
                        echoOffset = 0;
                        writeInPRSandCert(buf);
                    }
                    else
                    {
                        writeInContinueCert(buf);
                    }
                }
                apdu.setOutgoingAndSend(( short ) 0, ( short ) apduin.le);
                break;

            case ( byte ) 0x42:
                generateRSAKeyPair(apdu);
                break;
            case ( byte ) 0x43:
                reset();
                break;
            case ( byte ) 0x48:
                privateSignatual(apduin.p1, buf, apdu);
                break;
            case (byte)0xC0:
            	if(ptempCert.readSet == 0){
            		 ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            	}
                verifyCertLen(ptempCert.finashFlag);
                readCert(apdu, ptempCert);
            	break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * 参数： 该方法用于为应用读取公钥证书。 certTag：用于标识使用的证书； certBuff：输出证书数据的buff；
     * buffOffset：certBuff的起始偏移； sOffset：读证书数据的起始偏移； sLength：读证书数据的长度
     * 返回值：返回证书的剩余长度。
     */
    public short getCert(byte certTag, byte[] certBuff, short buffOffset, short sOffset, short sLength)
    {

        short len = 0;
        if (certTag == ( byte ) 0x53)
        {
            if (null == cert53)
            {
                return ( short ) 0xFFFF;
            }
            len = readCert(cert53, certBuff, buffOffset, sOffset, sLength);
            return len;
        }
        else if (certTag == ( byte ) 0x54)
        {
            if (null == cert54)
            {
                return ( short ) 0xFFFF;
            }
            len = readCert(cert54, certBuff, buffOffset, sOffset, sLength);
            return len;
        }
        else if (certTag == ( byte ) 0x55)
        {
            if (null == cert55)
            {
                return ( short ) 0xFFFF;
            }
            len = readCert(cert55, certBuff, buffOffset, sOffset, sLength);
            return len;
        }
        else
        {
            if (null == cert56)
            {
                return ( short ) 0xFFFF;
            }
            len = readCert(cert56, certBuff, buffOffset, sOffset, sLength);
            return len;
        }

    }

    private short readCert(Cert cert, byte[] certBuff, short buffOffset, short sOffset, short sLength)
    {

        // copyAndPadCert(cert.data, cert.certDataLen);
        if (!cert.decryFlag)
        {
            encryptCert(cert, certBuff);
        }
        if (sOffset + sLength >= cert.certDataLen)
        {
            short tLen = ( short ) (cert.certDataLen - sOffset);
            Util.arrayCopy(cert.data, sOffset, certBuff, ( short ) 0, tLen);
            sOffset = 0;
            return 0;
        }
        else
        {
            Util.arrayCopy(cert.data, sOffset, certBuff, ( short ) 0, sLength);
            sOffset += sLength;
            return ( short ) (cert.certDataLen - sOffset);
        }
    }

    private void encryptCert(Cert cert, byte[] certBuff)
    {

        short certLen = copyAndPadCert(cert.data, cert.certDataLen);
        tempCert.certDataLen = ( short ) (certLen + 4);
        short num = ( short ) ((certLen - 1) / Contents.MAX_DECRYPTLEN + 1);
        short pos = 4;

        for (short i = 0; i < num; i++)
        {
            if (i == (num - 1))
            {
                short tLen = ( short ) (certLen - pos + 4);
                Util.arrayCopy(tempCert.data, pos, certBuff, ( short ) 0, tLen);
                Util.arrayCopy(certBuff, ( short ) 0, tempCert.data, pos, tLen);
                pos += tLen;
            }
            else
            {
                Util.arrayCopy(tempCert.data, pos, certBuff, ( short ) 0, Contents.MAX_DECRYPTLEN);
                Util.arrayCopy(certBuff, ( short ) 0, tempCert.data, pos, Contents.MAX_DECRYPTLEN);
                pos += Contents.MAX_DECRYPTLEN;
            }
        }
        addPading(tempCert);
        cert.decryFlag = true;
    }

    /**
     * 方 法 名：encryption<br>
     * 功能描述：该方法用于为金融应用提供加密服务，使用参数中的密钥版本来指定要使用哪个非对称密钥来完成加密的操作。<br>
     * 
     * @param keyRef 用于标识使用的密钥的版本号和ID；
     * @param buffer 输入待加密数据所在的buffer；
     * @param sOffset 输入待加密数据在buffer中的起始偏移；
     * @param sLength 输入加密数据的长度；
     * @param encBuffer 加密后的结果存放的数组；
     * @param destOffet 加密后的结果在encBuffer中存放的起始位置；
     * @return short型，返回加密结果数据的长度。
     */
    public short encrypt(short keyRef, byte[] buffer, short sOffset, short sLength, byte[] encBuffer, short destOffet)
    {

        short encLen = 0;
        if (keyRef == ( short ) 0x7A02)
        {
            if (null == keyPair7A)
            {
                return ( short ) 0xFFFF;
            }
            encLen = encry(buffer, sOffset, sLength, buffer, destOffet, keyPair7A);
            Util.arrayCopy(buffer, ( short ) 0, encBuffer, ( short ) 0, encLen);
            return encLen;
        }
        else if (keyRef == ( short ) 0x7B02)
        {
            if (null == keyPair7B)
            {
                return ( short ) 0xFFFF;
            }
            encLen = encry(buffer, sOffset, sLength, buffer, destOffet, keyPair7B);
            Util.arrayCopy(buffer, ( short ) 0, encBuffer, ( short ) 0, encLen);
            return encLen;
        }
        else if (keyRef == ( short ) 0x7C02)
        {
            if (null == keyPair7C)
            {
                return ( short ) 0xFFFF;
            }
            encLen = encry(buffer, sOffset, sLength, buffer, destOffet, keyPair7C);
            Util.arrayCopy(buffer, ( short ) 0, encBuffer, ( short ) 0, encLen);
            return encLen;
        }
        else 
        {
            return ( short ) 0xFFFF;
        }
    }

    /**
     * 
     * @param inBuff 需要签名的数据
     * @param inOffset 签名数据的起始位置
     * @param inLength 签名数据的长度
     * @param outBuff 签名后数据存放的数组
     * @param outOffset 签名后数据存放的起始位置
     * @param keyPair
     * @return 返回-1表示加密过程init/dofinal出现安全异常
     */
    public short encry(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset, KeyPair keyPair)
    {

        PrivateKey priKey = ( PrivateKey ) keyPair.getPrivate();
        try
        {
            rsaCipher.init(priKey, Cipher.MODE_ENCRYPT);
        }
        catch (Exception e)
        {
                return ( short ) 0xFFFF;
        }
        short len = 0;
        try
        {
            len = rsaCipher.doFinal(inBuff, inOffset, inLength, outBuff, outOffset);
        }
        catch (Exception e)
        {
                return ( short ) 0xFFFF;
        }
        return len;
    }

    /**
     * 方 法 名：decryption<br>
     * 功能描述：该方法用于为金融应用提供解密服务，使用参数中的密钥版本来指定要使用哪个非对称密钥来完成解密的操作。<br>
     * 
     * @param keyRef ，用于标识使用的密钥的版本号和ID；
     * @param buffer 输入待解密数据所在的buffer；
     * @param sOffset 输入待解密数据在buffer中的起始偏移；
     * @param sLength 输入待解密数据的长度；
     * @param dekBuffer 解密后的结果存放的数组；
     * @param destOffet 解密后的结果在dekBuffer中存放的起始位置；
     * @return short型，返回解密操作的结果长度。
     */
    public short decrypt(short keyRef, byte[] buffer, short sOffset, short sLength, byte[] dekBuffer, short destOffet)
    {

        short decRestLen = 0;
        if (keyRef == ( short ) 0x7A02)
        {
            if (null == keyPair7A)
            {
                return ( short ) 0xFFFF;
            }
            decRestLen = decry(buffer, sOffset, sLength, dekBuffer, destOffet, keyPair7A);
            return decRestLen;
        }
        else if (keyRef == ( short ) 0x7B02)
        {
            if (null == keyPair7B)
            {
                return ( short ) 0xFFFF;
            }
            decRestLen = decry(buffer, sOffset, sLength, dekBuffer, destOffet, keyPair7B);
            return decRestLen;
        }
        else if (keyRef == ( short ) 0x7C02)
        {
            if (null == keyPair7C)
            {
                return ( short ) 0xFFFF;
            }
            decRestLen = decry(buffer, sOffset, sLength, dekBuffer, destOffet, keyPair7C);
            return decRestLen;
        }
        else 
        {
            return ( short ) 0xFFFF;
        }
    }

    private short decry(byte[] buffer, short sOffset, short sLength, byte[] dekBuffer, short destOffet, KeyPair keyPair)
    {

//        RSAPublicKey pubKey = ( RSAPublicKey ) keyPair.getPublic();
        PrivateKey priKey = ( PrivateKey ) keyPair.getPrivate();
        try
        {
            rsaCipher.init(priKey, Cipher.MODE_DECRYPT);
        }
        catch (Exception e)
        {
            return ( short ) 0xFFFF;
        }
        short len=0;
        try
        {
            len = rsaCipher.doFinal(buffer, sOffset, sLength, dekBuffer, destOffet);
        }
        catch (Exception e)
        {
            return ( short ) 0xFFFF;
        }
        return len;
    }

    /**
     * 
     * @param keyRef 用于标识使用的私钥，由密钥版本//密钥ID构成；
     * @param buffer 输入待签名数据所在的buffer；
     * @param sOffset 输入待签名数据在buffer中的起始偏移；
     * @param sLength 输入签名数据的长度
     * @param sigBuffer 签名后的结果存放的数组；
     * @param destOffet 签名后的结果在sigBuffer中存放的起始位置；
     * @return 返回签名结果数据的长度
     */
    public short sign(short keyRef, byte[] buffer, short sOffset, short sLength, byte[] sigBuffer, short destOffet)
    {
/**
        short signLen = 0;
        if (keyRef == ( short ) 0x7A02)
        {
            if (null == keyPair7A)
            {
                return ( short ) 0xFFFF;
            }
            // 传过来的数组sigBuffer不能存储直接dofinal加密，在本类new的可以。
            signLen = signature(buffer, sOffset, sLength, sigBuffer, destOffet, keyPair7A);
            Util.arrayCopy(buffer, ( short ) 0, sigBuffer, ( short ) 0, signLen);
            return signLen;
        }
        else if (keyRef == ( short ) 0x7B02)
        {
            if (null == keyPair7B)
            {
                return ( short ) 0xFFFF;
            }
            signLen = signature(buffer, sOffset, sLength, buffer, destOffet, keyPair7B);
            Util.arrayCopy(buffer, ( short ) 0, sigBuffer, ( short ) 0, signLen);
            return signLen;
        }
        else
        {
            if (null == keyPair7C)
            {
                return ( short ) 0xFFFF;
            }
            signLen = signature(buffer, sOffset, sLength, buffer, destOffet, keyPair7C);
            Util.arrayCopy(buffer, ( short ) 0, sigBuffer, ( short ) 0, signLen);
            return signLen;
        }
        */
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        return ( short ) 0xFFFF;
        
    }

    /**
     * 
     * @param inBuff 需要签名的数据
     * @param inOffset 签名数据的起始位置
     * @param inLength 签名数据的长度
     * @param outBuff 签名后数据存放的数组
     * @param outOffset 签名后数据存放的起始位置
     * @param keyPair
     * @return 返回-1表示加密过程init/dofinal出现安全异常
     */
    public short signature(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset,
                           KeyPair keyPair)
    {

        PrivateKey priKey = ( PrivateKey ) keyPair.getPrivate();
        try
        {
            signature.init(priKey, Signature.MODE_SIGN);
        }
        catch (Exception e)
        {
            return ( short ) 0xFFFF;
        }
        short len = 0;
        try
        {
            len = signature.sign(inBuff, inOffset, inLength, outBuff, outOffset);
        }
        catch (Exception e)
        {
            return ( short ) 0xFFFF;
        }
        return len;
    }

    /**
     * 
     * @param keyRef 用于标识使用的公钥ID，密钥版本//密钥ID构成；
     * @param buffer 输入待签名数据所在的buffer；
     * @param sOffset 输入待签名数据在buffer中的起始偏移；
     * @param sLength 输入签名数据的长度
     * @param sigBuffer 待验证的签名结果存放的数组；
     * @param sigOffet 待验证的签名结果在sigBuffer中存放的起始位置；
     * @param sigLength 签名数据的字节长度
     * @return 签名验证是否通过
     */
    public boolean verify(short keyRef, byte[] buffer, short sOffset, short sLength, byte[] sigBuffer, short sigOffet,
                          short sigLength)
    {
/**
        boolean flag = false;
        if (keyRef == ( short ) 0x7A)
        {
            flag = verification(buffer, sOffset, sLength, sigBuffer, sigOffet, sigLength, keyPair7A);
            return flag;
        }
        else if (keyRef == ( short ) 0x7B)
        {
            flag = verification(buffer, sOffset, sLength, sigBuffer, sigOffet, sigLength, keyPair7B);
            return flag;
        }
        else
        {
            flag = verification(buffer, sOffset, sLength, sigBuffer, sigOffet, sigLength, keyPair7C);
            return flag;
        }
        */
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        return false;
        
    }

    private boolean verification(byte[] buffer, short sOffset, short sLength, byte[] sigBuffer, short sigOffet,
                                 short sigLength, KeyPair keyPair)
    {

        RSAPublicKey pubKey = ( RSAPublicKey ) keyPair.getPublic();
        try
        {
            signature.init(pubKey, Signature.MODE_VERIFY);
        }
        catch (Exception e)
        {
            return false;
        }
        try
        {
            
            if (!flagD)
            {
                Util.arrayCopy(buffer, ( short ) sOffset, signed, ( short ) 0, ( short ) sLength);
                flagD=true;
                //存储待签名数据,返回9000 
                return true;
            }
            else
            {
                Util.arrayCopy(buffer, ( short ) sigOffet, signData, ( short ) 0, ( short ) sigLength);
            }
            boolean veryResult=signature.verify(signed, ( short ) 0, (short)sLength, signData,( short ) 0,(short) sigLength);
            if(veryResult)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        catch (Exception e)
        {
            //512长度的keypair报SecurityException
            return false;
        }
       
    }

    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter)
    {

        return this;
    }

    // ------------------------------------------------------------------
    private void privateSignatual(byte p1, byte[] buf, APDU apdu)
    {

        if (p1 == ( byte ) 0x7A)
        {
            signatual(p1, buf, apdu, keyPair7A);
        }
        else if (p1 == ( byte ) 0x7B)
        {
            signatual(p1, buf, apdu, keyPair7B);
        }
        else
        {
            signatual(p1, buf, apdu, keyPair7C);
        }
    }

    private void signatual(byte p1, byte[] buf, APDU apdu, KeyPair keyPair)
    {

        PrivateKey priKey = ( PrivateKey ) keyPair.getPrivate();
        rsaCipher.init(priKey, Cipher.MODE_ENCRYPT);
        rsaCipher.doFinal(buf, ( short ) 5, ( short ) 128, buf, ( short ) 0);
        apdu.setOutgoingAndSend(( short ) 0, ( short ) 128);
    }

    /**
     * 填充证书需要加密的数据为8的倍数
     * 
     * @param arr 证书数据
     * @param set 证书长度
     * @return 需要加密的数据
     */
    private short copyAndPadCert(byte[] arr, short set)
    {

        short pos = 0;
        while (true)
        {
            if (pos + Contents.MAX_COPYLEN >= set)
            {
                Util.arrayCopy(arr, pos, tempCert.data, pos, ( short ) (set - pos));
                break;
            }
            else
            {
                Util.arrayCopy(arr, pos, tempCert.data, pos, Contents.MAX_COPYLEN);
                pos += Contents.MAX_COPYLEN;
            }
        }
        tempCert.data[set] = ( byte ) 0x80;
        short certPadLen = ( short ) (((set - 4) / 8 + 1) * 8);
        for (short i = ++set; i < certPadLen + 4; i++)
        {
            tempCert.data[i] = ( byte ) 0x00;
        }
        tempCert.data[3] = ( byte ) (certPadLen & 0xFF);
        tempCert.data[2] = ( byte ) (certPadLen >> 8 & 0xFF);
        return certPadLen;
    }

    /**
     * 加密证书
     * 
     * @param buf apdu缓存
     * @param arr 证书数据
     * @param set 证书长度
     */
    private void encryptCert(byte[] buf, Cert cert)
    {

        short certLen = copyAndPadCert(cert.data, cert.certDataLen);
        tempCert.certDataLen = ( short ) (certLen + 4);
        short num = ( short ) ((certLen - 1) / Contents.MAX_DECRYPTLEN + 1);
        short pos = 4;
        for (short i = 0; i < num; i++)
        {
            if (i == (num - 1))
            {
                short tLen = ( short ) (certLen - pos + 4);
                Util.arrayCopy(tempCert.data, pos, buf, ( short ) 0, tLen);
                encrypt(buf, tLen);
                Util.arrayCopy(buf, ( short ) 0, tempCert.data, pos, tLen);
                pos += tLen;
            }
            else
            {
                Util.arrayCopy(tempCert.data, pos, buf, ( short ) 0, Contents.MAX_DECRYPTLEN);
                encrypt(buf, Contents.MAX_DECRYPTLEN);
                Util.arrayCopy(buf, ( short ) 0, tempCert.data, pos, Contents.MAX_DECRYPTLEN);
                pos += Contents.MAX_DECRYPTLEN;
            }
        }
        addPading(tempCert);
        cert.decryFlag = true;
    }

    /**
     * 对非加密方式，最后添加FFFF作为标记
     * 
     * @param cert
     */
    private void addPading(Cert cert)
    {

        if (!CERTENCRYPTFLAG)
        {
            tempCert.data[tempCert.certDataLen] = ( byte ) 0xFF;
            tempCert.data[tempCert.certDataLen + 1] = ( byte ) 0xFF;
            tempCert.certDataLen += 2;
        }
    }

    /**
     * 根据FLAG的不同设置不同的安全处理方式
     * 
     * @param data
     * @param len
     */
    private void encrypt(byte[] data, short len)
    {

        if (CERTENCRYPTFLAG)
        {
            secureChannel.encryptData(data, ( short ) 0, len);
        }
        else
        {
            secureChannel.decryptData(data, ( short ) 0, len);
        }
    }

    /**
     * 读取公钥
     * 
     * @param pubKey
     * @param priKey
     * @param keyP
     * @param tag
     * @param buf
     * @param certData
     */
    private short readPubKey(KeyPair keyP, byte[] tag, byte[] buf)
    {
        buf[0] = ( byte ) 0xC3;
        buf[1] = ( byte ) 0x81;
        short size = getPubData(keyP,buf,(short)3);
        buf[2] = ( byte ) size;
        return ( short ) (size + 3);
    }
    
    private short getPubData(KeyPair keyP,byte[] buf,short tagLen){
    	RSAPublicKey pubKey = ( RSAPublicKey ) keyP.getPublic(); /* 取得到RSA公钥 */
    	
    	short modLen = pubKey.getModulus(buf, ( short ) tagLen); /* 取得到RSA的模 */
        short expLen = pubKey.getExponent(tempPub, ( short ) 0);/* 得到RSA的指数 */
        Util.arrayCopy(tempPub, ( short ) (expLen - 3), buf, ( short ) (modLen + tagLen + 1), (short)3);
        
        return (short)(modLen + 4);   	
    }

    private void getData(byte p1, APDU apdu)
    {

        if (( byte ) 0x00 == p1)
        {
            readPSRandCert(apdu);
        }
        else
        {
            readPubKey(apdu);
        }
    }

    /**
     * 读取pamid rid securityLevel
     * 
     * @param ap
     */
    private void readPSRandCert(APDU ap)
    {

        byte[] buffer = ap.getBuffer();
        switch (buffer[ISO7816.OFFSET_P2])
        {

            case ( byte ) 0x50:
                Util.arrayCopy(pamidset, ( short ) 0, buffer, ( short ) 0, ( short ) 18);
                ap.setOutgoingAndSend(( short ) 0, ( short ) 18);
                break;
            case ( byte ) 0x51:
                Util.arrayCopy(ridset, ( short ) 0, buffer, ( short ) 0, ( short ) 20);
                ap.setOutgoingAndSend(( short ) 0, ( short ) 7);
                break;
            case ( byte ) 0x52:
                Util.arrayCopy(scset, ( short ) 0, buffer, ( short ) 0, ( short ) 18);
                ap.setOutgoingAndSend(( short ) 0, ( short ) 3);
                break;
            case ( byte ) 0x53:
            	ptempCert.Copy(cert53);
	            verifyCertLen(ptempCert.finashFlag);
	            readCert(ap, ptempCert);
	            break;
            case ( byte ) 0x54:
            	ptempCert.Copy(cert54);
	            verifyCertLen(ptempCert.finashFlag);
	            readCert(ap, ptempCert);
                break;
            case ( byte ) 0x55:
            	ptempCert.Copy(cert55);
	            verifyCertLen(ptempCert.finashFlag);
	            readCert(ap, ptempCert);
                break;
            case ( byte ) 0x56:
            	ptempCert.Copy(cert56);
                verifyCertLen(ptempCert.finashFlag);
                readCert(ap, ptempCert);
                break;
            case ( byte ) 0x57:
                Util.arrayCopy(buffer, ( short ) ISO7816.OFFSET_LC, buffer, ( short ) 0, ( short ) (buffer[ISO7816.OFFSET_LC]+1));
                ap.setOutgoingAndSend(( short ) 0, ( short ) (buffer[ISO7816.OFFSET_LC]+1));
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * 读取证书 根据卡片API的不同，证书读取支持加密和解密两种方式 如果使用解密方法保护则在数据的尾部增加两个字节的FF。
     * 
     * @param ap
     * @param cert
     */
    private void readCert(APDU ap, Cert cert)
    {

        byte[] buffer = ap.getBuffer();

        if (!cert.decryFlag)
        {
            encryptCert(buffer, cert);
        }

        if (cert.readSet + Contents.MAX_RESLEN >= tempCert.certDataLen)
        {
            short tLen = ( short ) (tempCert.certDataLen - cert.readSet);
            Util.arrayCopy(tempCert.data, cert.readSet, buffer, ( short ) 0, tLen);
            ap.setOutgoingAndSend(( short ) 0, ( short ) tLen);
            
            cert.decryFlag = false;
            cert.readSet = 0;
        }
        else
        {

            Util.arrayCopy(tempCert.data, cert.readSet, buffer, ( short ) 0, Contents.MAX_RESLEN);
            ap.setOutgoingAndSend(( short ) 0, ( short ) Contents.MAX_RESLEN);
            cert.readSet += Contents.MAX_RESLEN;
            
            if (cert.readSet + Contents.MAX_RESLEN >= tempCert.certDataLen){
                ISOException.throwIt((short)((short)0x6100 + (short)(tempCert.certDataLen - cert.readSet)));
            }else{
                ISOException.throwIt((short)0x6100);
            }
        }
    }

    private short readKeyData(KeyPair keyP, byte[] buf, byte[] tag)
    {
        buf[0] = tag[0];
        buf[1] = tag[1];
        buf[2] = ( byte ) 0x81;
        short size = getPubData(keyP,buf,(short)4);
        buf[3] = ( byte ) size;
        return ( short ) (size + 4);
    }

    /**
     * 读取7A 7B 7C密钥
     * 
     * @param apdu
     */
    private void readPubKey(APDU apdu)
    {

        byte[] buf = apdu.getBuffer();
        switch (buf[ISO7816.OFFSET_P1])
        {
            case ( byte ) 0x7A:
                byte[] tagA = { ( byte ) 0x7A, ( byte ) 0x01 };
                short lenA = readKeyData(keyPair7A, buf, tagA);
                apdu.setOutgoingAndSend(( short ) 0, ( short ) lenA);
                break;
            case ( byte ) 0x7B:
                byte[] tagB = { ( byte ) 0x7B, ( byte ) 0x01 };
                short lenB = readKeyData(keyPair7B, buf, tagB);
                apdu.setOutgoingAndSend(( short ) 0, ( short ) lenB);
                break;
            case ( byte ) 0x7c:
                byte[] tagC = { ( byte ) 0x7C, ( byte ) 0x01 };
                short lenC = readKeyData(keyPair7C, buf, tagC);
                apdu.setOutgoingAndSend(( short ) 0, ( short ) lenC);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * 写入pamid rid securityLevel 以及四个证书的头一条指令
     * 
     * @param buf
     */
    private void writeInPRSandCert(byte[] buf)
    {

        caseValue = buf[8];
        if (buf[7] == ( byte ) 0x81)
        {
            caseValue = buf[9];
            echoOffset += ( short ) (buf[4] & 0xFF) - 4;
            certDataLen = ( short ) (buf[8] & 0xFF);
        }
        else if (buf[7] == ( byte ) 0x82)
        {
            caseValue = buf[10];
            echoOffset += ( short ) (buf[4] & 0xFF) - 5;
            certDataLen = ( short ) ((buf[8] & 0xFF) * 256 + (buf[9] & 0xFF));
        }

        switch (caseValue)
        {
            case ( byte ) 0x50:

                if (pamidset[0] == ( byte ) 0x00)
                {
                    Util.arrayCopy(buf, ( short ) 8, pamidset, ( short ) 0, ( short ) (apduin.lc - 3));
                }
                else
                {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                break;
            case ( byte ) 0x51:
                Util.arrayCopy(buf, ( short ) 8, ridset, ( short ) 0, ( short ) (apduin.lc - 3));
                break;
            case ( byte ) 0x52:
                Util.arrayCopy(buf, ( short ) 8, scset, ( short ) 0, ( short ) (apduin.lc - 3));
                break;
            case ( byte ) 0x53:
                cert53.writeFirstData(buf, echoOffset, certDataLen);
                cert53.resetWFlag(cert54).resetWFlag(cert55).resetWFlag(cert56);
                break;
            case ( byte ) 0x54:
                cert54.writeFirstData(buf, echoOffset, certDataLen);
                cert54.resetWFlag(cert53).resetWFlag(cert55).resetWFlag(cert56);
                break;
            case ( byte ) 0x55:
                cert55.writeFirstData(buf, echoOffset, certDataLen);
                cert55.resetWFlag(cert53).resetWFlag(cert54).resetWFlag(cert56);
                break;
            case ( byte ) 0x56:
                cert56.writeFirstData(buf, echoOffset, certDataLen);
                cert56.resetWFlag(cert53).resetWFlag(cert54).resetWFlag(cert55);
                break;
            default:

                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * 写入证书的剩余部分
     * 
     * @param buf
     */
    private void writeInContinueCert(byte[] buf)
    {

        cert53.writeOtherData(buf);
        cert54.writeOtherData(buf);
        cert55.writeOtherData(buf);
        cert56.writeOtherData(buf);
    }

    private void verifyCertLen(boolean finalflag)
    {

        if (!finalflag)
        {
            ISOException.throwIt(ISO7816.SW_CORRECT_LENGTH_00);
        }
    }

    /**
     * 生成7A 7B 7C的公私钥
     * 
     * @param apdu
     */
    private void generateRSAKeyPair(APDU apdu)
    {

        byte[] buf = apdu.getBuffer();

        byte[] tag = { ( byte ) 0xC3 };
        switch (buf[7])
        {
            case ( byte ) 0x7A:
                if (null == keyPair7A)
                {
                    keyPair7A = new KeyPair(KeyPair.ALG_RSA_CRT, ( short ) 1024);
                    keyPair7A.genKeyPair(); /* 生成密钥对 */
                }
                short s1 = readPubKey(keyPair7A, tag, buf);
                apdu.setOutgoingAndSend(( short ) 0, ( short ) s1);
                break;
            case ( byte ) 0x7B:
                if (null == keyPair7B)
                {
                    keyPair7B = new KeyPair(KeyPair.ALG_RSA_CRT, ( short ) 1024);
                    keyPair7B.genKeyPair();
                }
                short s2 = readPubKey(keyPair7B, tag, buf);
                apdu.setOutgoingAndSend(( short ) 0, ( short ) s2);
                break;
            case ( byte ) 0x7c:
                if (null == keyPair7C)
                {
                    keyPair7C = new KeyPair(KeyPair.ALG_RSA_CRT, ( short ) 1024);
                    keyPair7C.genKeyPair();
                }
                short s3 = readPubKey(keyPair7C, tag, buf);
                apdu.setOutgoingAndSend(( short ) 0, ( short ) s3);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * 外部认证
     * 
     * @param buf
     * @param apdu
     */
    private boolean extAuth(byte[] buf, APDU apdu)
    {

        if (( byte ) 0x80 == buf[ISO7816.OFFSET_CLA] && ( byte ) 0x50 == buf[ISO7816.OFFSET_INS])
        {
            extAuthFlg = false;
            secureChannel.resetSecurity();
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, secureChannel.processSecurity(apdu));

            return true;

        }
        else if ((( byte ) 0x84 == buf[ISO7816.OFFSET_CLA] && ( byte ) 0x82 == buf[ISO7816.OFFSET_INS]))
        {
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, secureChannel.processSecurity(apdu));
            if (!(buf[ISO7816.OFFSET_P1] == ( byte ) 03))
            {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            extAuthFlg = true;
            return true;
        }
        return false;

    }

    /**
     * 指令合法性检查
     * 
     * @param buf
     * @param apdu
     */
    private void secureCheck(byte[] buf, APDU apdu)
    {

        // 检查数据完整
        apduin.cla = buf[ISO7816.OFFSET_CLA];
        apduin.ins = buf[ISO7816.OFFSET_INS];
        apduin.p1 = buf[ISO7816.OFFSET_P1];
        apduin.p2 = buf[ISO7816.OFFSET_P2];
        apduin.lc = ( short ) (buf[ISO7816.OFFSET_LC] & 0x0FF);

        // 判断是否是FCSD支持的指令
        if (!apduin.APDUContainData())
        {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        short apduLength = 0;
        if (apduin.lc > 0)
            apduLength = apdu.setIncomingAndReceive();

        if (apduLength != apduin.lc)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
    }

    /**
     * reset method
     */
    private void reset()
    {

        // RID重置
        Util.arrayFillNonAtomic(ridset, ( short ) 0, ( short ) ridset.length, ( byte ) 0x00);
        // 安全等级重置
        Util.arrayFillNonAtomic(scset, ( short ) 0, ( short ) scset.length, ( byte ) 0x00);
        // 证书重置
        cert53.clear();
        cert54.clear();
        cert55.clear();
        cert56.clear();
        // 临时证书
        tempCert.clear();
        // 验证标记
        extAuthFlg = false;
        // 安全通道
        secureChannel.resetSecurity();

        apduin.clear();
        // TODO
        keyPair7A = null;
        keyPair7B = null;
        keyPair7C = null;

        JCSystem.requestObjectDeletion();
    }

    /**
     * 指令的合法性检查，外部认证，指令解密处理
     * 
     * @param apdu
     * @return
     */
    private byte[] apduSecurityManager(APDU apdu)
    {

        // 获取指令数据
        byte[] buf = apdu.getBuffer();
        buf[0] = ( byte ) (buf[0] & 0xFC);

        // 指令合法性检查
        secureCheck(buf, apdu);

        // 外部认证
        if (extAuth(buf, apdu))
        {
            return null;
        }

        // 判断外部认证是否成功
        if (!extAuthFlg)
        {
            if (!(( byte ) 0xCA == buf[ISO7816.OFFSET_INS] && ( byte ) 0x50 == buf[ISO7816.OFFSET_P2]))
            {
                ISOException.throwIt(Contents.SW_E_AUTH_FAIL);
            }
        }

        // 解密APDU指令
        if((( byte ) 0x84 == buf[ISO7816.OFFSET_CLA]) || (( byte ) 0x04 == buf[ISO7816.OFFSET_CLA]))
        {
                short len = ( short ) (buf[ISO7816.OFFSET_LC] & 0x0FF);
                secureChannel.unwrap(buf, ( short ) 0, ( short ) (len + 5));
        }
        buf[0] = ( byte ) (buf[0] & 0xFC);
        return buf;
    }

    /**
     * 证书初始化管理
     */
    private void certInitManager()
    {

        // 重置四种证书的读取标志与加密标志
        if (apduin.ins == ( byte ) 0xCA)
        {
            if (apduin.p2 == ( byte ) 0x53)
            {
                cert54.readSet = ( short ) 0;
                cert54.decryFlag = false;
                cert55.readSet = ( short ) 0;
                cert55.decryFlag = false;
                cert56.readSet = ( short ) 0;
                cert56.decryFlag = false;
            }
            if (apduin.p2 == ( byte ) 0x54)
            {
                cert53.readSet = ( short ) 0;
                cert53.decryFlag = false;
                cert55.readSet = ( short ) 0;
                cert55.decryFlag = false;
                cert56.readSet = ( short ) 0;
                cert56.decryFlag = false;
            }
            if (apduin.p2 == ( byte ) 0x55)
            {
                cert53.readSet = ( short ) 0;
                cert53.decryFlag = false;
                cert54.readSet = ( short ) 0;
                cert54.decryFlag = false;
                cert56.readSet = ( short ) 0;
                cert56.decryFlag = false;
            }
            if (apduin.p2 == ( byte ) 0x56)
            {
                cert53.readSet = ( short ) 0;
                cert53.decryFlag = false;
                cert54.readSet = ( short ) 0;
                cert54.decryFlag = false;
                cert55.readSet = ( short ) 0;
                cert55.decryFlag = false;
            }
        }
    }

}
