import java.security.MessageDigest;

import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.jcajce.provider.digest.SHA3.Digest256;

import java.util.*;
//
public class TestSha3 {

    public static void main(String[] args) {

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
		b1 =zeroByte(h1tmp, h0, id);
		String Bh1 = hashToString(b1);
		id=2;
		b2 =zeroByte(Bh1, h0, id);
    }
	public static byte [] zeroByte(String hr, String h0, int id){
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
        System.out.println("Add a New Block 'a' : h"+id+" = SHA3("+h0+"\n\t\t\t\t|| a || "+r+")");
        System.out.println("\t\t\t = "+Bh1);
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
