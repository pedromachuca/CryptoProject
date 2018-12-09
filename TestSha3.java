import java.security.MessageDigest;

import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.jcajce.provider.digest.SHA3.Digest256;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.crypto.generators.ECKeyPairGenerator;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import org.bouncycastle.crypto.signers.ECDSASigner;

import org.bouncycastle.math.ec.ECPoint;

import org.bouncycastle.crypto.*;


import java.security.*;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.sec.SECNamedCurves;

import org.bouncycastle.asn1.ASN1Encodable;

import java.math.BigInteger;



import java.util.*;

public class TestSha3 {

  public static void main(String[] args) {

    Security.addProvider(new BouncyCastleProvider());

    System.out.println("\n*** SHA3 Vector Tests ***");
    System.out.println("''    -> "+sha3String(""));
    System.out.println("'abc' -> "+sha3String("abc")+"\n");

    System.out.println("*** Hash Chain ***");
  	String h0 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    System.out.println("Init the Hash Chain : h0 = "+h0);
  	String h1tmp = h0+"a";
  	String h1 = sha3String(h1tmp);
    System.out.println("Add a New Block 'a' : h1 = "+h1);
  	String h2 = h1+"b";
    System.out.println("Add a New Block 'b' : h2 = "+sha3String(h2)+"\n");

  	System.out.println("*** Hash Chain with Proof of Work ***");
    System.out.println("Init the Hash Chain : h0 = "+h0);
  	byte[] b1 = new byte[32];
  	byte[] b2 = new byte[32];
  	int id=1;
    String H = "a";
  	b1 =zeroByte(h1tmp, h0, id, H);
  	String Bh1 = hashToString(b1);
  	id=2;
    H= "b";
  	b2 =zeroByte(Bh1, h0, id, H);

    System.out.println("\n*** Key Generation ***");

    try{

      byte [] vk1 =generatePrivate();//Genrate public wired but for testing
      byte [] vk2 =generatePrivate();
      byte [] vk3 =generatePrivate();
      //
      // byte [] sk1 =generatePrivate();
      AsymmetricCipherKeyPair pair = generatePublic();
      System.out.println("Wallet 1 = vk1 = "+Hex.toHexString(vk1));
      System.out.println("Wallet 1 = vk2 = "+Hex.toHexString(vk2));
      System.out.println("Wallet 1 = vk3 = "+Hex.toHexString(vk3));
      //
      //
      System.out.println("\n*** BlockChain of Transactions  ***");
      System.out.println("Init the Hash Chain: h0 = "+h0);
      String block = Hex.toHexString(vk1)+" receives 10 Euros";
      // System.out.println("Add a New Block '"+block+"'");
      id =1;
      H =block;
      zeroByte(block, h0, id, H);
      String block1 = Hex.toHexString(vk1)+" gives 5 Euros to "+Hex.toHexString(vk2);
      System.out.println("Add a New Block '"+Hex.toHexString(vk1)+"\n\t\t    gives 5 Euros to "+Hex.toHexString(vk2)+"'");
      // //"vk1 transfert 5€ à vk2" || signature sous sk1
      String testSig = Hex.toHexString(vk1)+"gives 5 Euros to"+Hex.toHexString(vk2);
      BigInteger[] test = signature(pair.getPrivate(), testSig.getBytes());
      System.out.println("Sig[0] :"+test[0].toString(16)+"\nSig[1] :"+test[1].toString(16));

      // byte [] testSig =generateSignature(sk1, block1.getBytes());
      // System.out.println("testSig :"+Hex.toHexString(testSig));
    }catch(GeneralSecurityException e){
      System.out.println(e.getMessage());
    }


  }

// Une bonne base pour générer des clefs
// Fouiller la bibliothèque (la doc BouncyCastle) pour trouver les paramètres dont vous avez besoin

  public static byte[] generatePrivate()throws GeneralSecurityException{

    ECKeyPairGenerator g = new ECKeyPairGenerator();
    SecureRandom secureRandom = new SecureRandom();
    X9ECParameters secnamecurves = SECNamedCurves.getByName("secp256k1");
    ECDomainParameters ecParams = new ECDomainParameters(secnamecurves.getCurve(), secnamecurves.getG(), secnamecurves.getN(), secnamecurves.getH());
    ECKeyGenerationParameters keyGenParam = new ECKeyGenerationParameters(ecParams, secureRandom);
    g.init(keyGenParam);
    AsymmetricCipherKeyPair pair = g.generateKeyPair();
    ECPrivateKeyParameters privatekey = (ECPrivateKeyParameters)pair.getPrivate();
    ECPoint dd = secnamecurves.getG().multiply(privatekey.getD());
    byte[] publickey = dd.getYCoord().toBigInteger().toByteArray();
    byte [][] keys = new byte[][]{privatekey.getD().toByteArray(),publickey};

    return publickey;
  }
  public static AsymmetricCipherKeyPair generatePublic()throws GeneralSecurityException{

    ECKeyPairGenerator g = new ECKeyPairGenerator();
    SecureRandom secureRandom = new SecureRandom();
    X9ECParameters secnamecurves = SECNamedCurves.getByName("secp256k1");
    ECDomainParameters ecParams = new ECDomainParameters(secnamecurves.getCurve(), secnamecurves.getG(), secnamecurves.getN(), secnamecurves.getH());
    ECKeyGenerationParameters keyGenParam = new ECKeyGenerationParameters(ecParams, secureRandom);
    g.init(keyGenParam);
    AsymmetricCipherKeyPair pair = g.generateKeyPair();
    ECPrivateKeyParameters privatekey = (ECPrivateKeyParameters)pair.getPrivate();
    ECPoint dd = secnamecurves.getG().multiply(privatekey.getD());
    byte[] publickey = dd.getYCoord().toBigInteger().toByteArray();
    byte [][] keys = new byte[][]{privatekey.getD().toByteArray(),publickey};
    return pair;
  }


  public static BigInteger[] signature(CipherParameters privatekey, byte[] input) throws GeneralSecurityException{

    ECDSASigner signer = new ECDSASigner();
    signer.init(true, privatekey);
    final BigInteger[] signature = signer.generateSignature(input);
    return signature;
  }


  public static boolean verifySignature(CipherParameters privatekey, byte[] input, BigInteger [] signature) throws GeneralSecurityException{

    ECDSASigner verifier = new ECDSASigner();
    verifier.init(false, privatekey);
    boolean test =verifier.verifySignature(input, signature[0], signature[1]);
    return true;
  }

	public static byte [] zeroByte(String hr, String h0, int id, String H){
		boolean zero = true;
		byte [] b = new byte[8];
		byte [] b1 = new byte[32];
		String hr1;
		String r;

		do{
			b = generateRand();
			r = hashToString(b);
			hr1=hr+r;
			b1 = sha3byte(hr1);
			if(b1[31]==0&&b1[30]==0){
				zero =false;
			}
		}while(zero);

		String Bh1 = hashToString(b1);
    if(H.equals("a")||H.equals("b")){
      System.out.println("Add a New Block '"+H+"' : h"+id+" = SHA3("+h0+"\n\t\t\t\t|| "+H+" || "+r+")");
      System.out.println("\t\t\t = "+Bh1);
    }
    else {
      System.out.println("Add a New Block '"+H+"' \n   -> h"+id+" = SHA3("+h0+"\n\t\t|| "+H+"\n\t\t|| "+r+")");
      System.out.println("\t      = "+Bh1);
    }
		return b1;
	}


	public static byte [] generateRand(){

		byte [] b = new byte[8];
		new Random().nextBytes(b);
		return b;
	}

  static String sha3String(String input) {

    DigestSHA3 sha3 = new Digest256();
    sha3.update(input.getBytes());
    return TestSha3.hashToString(sha3);
  }

  static byte [] sha3byte(String input) {

    DigestSHA3 sha3 = new Digest256();
    sha3.update(input.getBytes());
		byte [] b =sha3.digest();
		return b;
	}

  static String hashToString(MessageDigest hash) {
    return hashToString(hash.digest());
  }

  static String hashToString(byte[] hash) {

    StringBuffer buff = new StringBuffer();

    for (byte b : hash) {
        buff.append(String.format("%02x", b & 0xFF));
    }
    return buff.toString();
  }
}
