import java.security.MessageDigest;
import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.jcajce.provider.digest.SHA3.Digest256;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;

import javax.crypto.Cipher;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.encoders.Hex;

 import java.security.*;
 import java.security.spec.ECGenParameterSpec;


// import org.bouncycastle.jce.spec.ECGenParameterSpec;


// import java.math.BigInteger;
// import org.bouncycastle.math.ec.*;
// import org.bouncycastle.jce.spec.*;

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

      KeyPair pair1 =generateKeyPair();
      KeyPair pair2 =generateKeyPair();
      KeyPair pair3 =generateKeyPair();

      PrivateKey sk1 = pair1.getPrivate();
      PublicKey vk1 = pair1.getPublic();
      byte [] pub1 =vk1.getEncoded();
      String vk1hextmp = Hex.toHexString(pub1);
      String[] vk1hex = vk1hextmp.split("3049301306072a8648ce3d020106082a8648ce3d0301010332000");

      PrivateKey sk2 = pair2.getPrivate();
      PublicKey vk2 = pair2.getPublic();
      byte [] pub2 =vk2.getEncoded();
      String vk2hextmp = Hex.toHexString(pub2);
      String[] vk2hex = vk2hextmp.split("3049301306072a8648ce3d020106082a8648ce3d0301010332000");

      PrivateKey sk3 = pair3.getPrivate();
      PublicKey vk3 = pair3.getPublic();
      byte [] pub3 =vk3.getEncoded();
      String vk3hextmp = Hex.toHexString(pub3);
      String[] vk3hex = vk3hextmp.split("3049301306072a8648ce3d020106082a8648ce3d0301010332000");

      System.out.println("Wallet 1 = vk1 = "+vk1hex[1]);
      System.out.println("Wallet 2 = vk2 = "+vk2hex[1]);
      System.out.println("Wallet 3 = vk3 = "+vk3hex[1]);

      System.out.println("\n*** BlockChain of Transactions  ***");
      System.out.println("Init the Hash Chain: h0 = "+h0);
      String block = vk1hex[1]+" receives 10 Euros";
      //System.out.println("Add a New Block '"+block+"'");
      id =1;
      H =block;
      zeroByte(block, h0, id, H);
      String block1 = vk1hex[1]+" gives 5 Euros to "+vk2hex[1];
      System.out.println("'"+block1+"'");
      //"vk1 transfert 5€ à vk2" || signature sous sk1
      // String
      byte [] testSig =generateSignature(sk1, block1.getBytes());
      System.out.println("testSig :"+Hex.toHexString(testSig));
    }catch(GeneralSecurityException e){
      System.out.println(e.getMessage());
    }


  }


  public static KeyPair generateKeyPair()throws GeneralSecurityException{

    ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime192v1");
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
    keyGen.initialize(ecSpec, new SecureRandom());
    KeyPair pair = keyGen.generateKeyPair();
    return pair;
  }


  public static byte[] generateSignature(PrivateKey ecPrivate, byte[] input) throws GeneralSecurityException{

    Signature signature = Signature.getInstance("SHA384withECDSA", "BC");
    signature.initSign(ecPrivate);
    signature.update(input);
    return signature.sign();
  }


  public static boolean verifySignature(PublicKey ecPublic, byte[] input, byte[] encSignature) throws GeneralSecurityException{

    Signature signature = Signature.getInstance("SHA384withECDSA", "BCFIPS");
    signature.initVerify(ecPublic);
    signature.update(input);
    return signature.verify(encSignature);
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
