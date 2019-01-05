import java.security.MessageDigest;

import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.jcajce.provider.digest.SHA3.Digest256;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.crypto.generators.ECKeyPairGenerator;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;

import org.bouncycastle.math.ec.ECPoint;

import java.security.*;
import java.util.*;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.sec.SECNamedCurves;

import java.math.BigInteger;

public class Blockchain {

  public static void main(String [] args){
		new Blockchain();
  }

  KeyGeneration keygen1 =null;
  KeyGeneration keygen2 =null;
  KeyGeneration keygen3 =null;

  public Blockchain(){
    Security.addProvider(new BouncyCastleProvider());
    display();

  }

  void display(){

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

    keygen1 = new KeyGeneration();
    keygen2 = new KeyGeneration();
    keygen3 = new KeyGeneration();

    byte [] vk1 = keygen1.publickey;
    byte [] vk2 = keygen2.publickey;
    byte [] vk3 = keygen3.publickey;

    System.out.println("Wallet 1 = vk1 = "+hashToString(vk1));
    System.out.println("Wallet 2 = vk2 = "+hashToString(vk2));
    System.out.println("Wallet 3 = vk3 = "+hashToString(vk3));

    System.out.println("\n*** BlockChain of Transactions  ***");
    System.out.println("Init the Hash Chain: h0 = "+h0);
    String block = hashToString(vk1)+" receives 10 Euros";
    // System.out.println("Add a New Block '"+block+"'");
    id =1;
    H =block;
    byte [] B1 = zeroByte(block, h0, id, H);
    String stringSig1 = hashToString(vk1)+" gives 5 Euros to "+hashToString(vk2);
  //  System.out.println("Add a New Block '"+hashToString(vk1)+"\n\t\t    gives 5 Euros to "+hashToString(vk2)+"'");

    BigInteger[] sign1=null;
    boolean verif1 = false;

    try{

      sign1 = keygen1.signature(keygen1.pair.getPrivate(),sha3byte(stringSig1));
      verif1 =keygen1.verifySignature(keygen1.pair.getPublic(),sha3byte(stringSig1), sign1);

    }catch(GeneralSecurityException e){System.out.println(e.getMessage());}

  //  System.out.println("\t\t|| "+sign1[0].toString(16));
   // System.out.println("\t\t|| "+sign1[1].toString(16)+"'");

    String H2 = hashToString(vk1)+"\n\t\t\tgives 5 Euros to "+hashToString(vk2)+"\n\t\t|| "+sign1[0].toString(16)+"\n\t\t|| "+sign1[1].toString(16);
    String block1 = hashToString(vk1)+"gives 5 Euros to"+hashToString(vk2)+sign1[0].toString(16)+sign1[1].toString(16);
    id=2;
    byte [] B2 = zeroByte(block1, hashToString(B1), id, H2);

    System.out.println("Validity of the signature : "+verif1);

    String stringSig2 = hashToString(vk1)+" gives 5 Euros to "+hashToString(vk3);
    BigInteger[] sign2=null;
    boolean verif2 = false;

    try{

      sign2 = keygen1.signature(keygen1.pair.getPrivate(),sha3byte(stringSig2));
      verif2 =keygen1.verifySignature(keygen1.pair.getPublic(),sha3byte(stringSig2), sign2);

    }catch(GeneralSecurityException e){System.out.println(e.getMessage());}

    String H3 = hashToString(vk1)+"\n\t\t\tgives 5 Euros to "+hashToString(vk3)+"\n\t\t|| "+sign2[0].toString(16)+"\n\t\t|| "+sign2[1].toString(16);

    String block2 = hashToString(vk1)+"gives 5 Euros to"+hashToString(vk3)+sign2[0].toString(16)+sign2[1].toString(16);
    id=3;
    zeroByte(block2, hashToString(B2), id, H3);

    System.out.println("Validity of the signature : "+verif2);

  }

  byte [] zeroByte(String hr, String h0, int id, String H){
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


  byte [] generateRand(){

    byte [] b = new byte[8];
    new Random().nextBytes(b);
    return b;
  }

  String sha3String(String input) {

    DigestSHA3 sha3 = new Digest256();
    sha3.update(input.getBytes());
    return hashToString(sha3);
  }

  byte [] sha3byte(String input) {
    DigestSHA3 sha3 = new Digest256();
    sha3.update(input.getBytes());
    byte [] b =sha3.digest();
    return b;
  }

  String hashToString(MessageDigest hash) {
    return hashToString(hash.digest());
  }

  String hashToString(byte[] hash) {

    StringBuffer buff = new StringBuffer();

    for (byte b : hash) {
        buff.append(String.format("%02x", b & 0xFF));
    }
    return buff.toString();
  }
}
