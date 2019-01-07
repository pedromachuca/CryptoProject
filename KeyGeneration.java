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

public class KeyGeneration{

  byte [] publickey;
  AsymmetricCipherKeyPair pair;

  public KeyGeneration(){

    Security.addProvider(new BouncyCastleProvider());
    ECKeyPairGenerator g = new ECKeyPairGenerator();
    SecureRandom secureRandom = new SecureRandom();
    X9ECParameters secnamecurves = SECNamedCurves.getByName("secp256k1");
    ECDomainParameters ecParams = new ECDomainParameters(secnamecurves.getCurve(), secnamecurves.getG(), secnamecurves.getN(), secnamecurves.getH());
    ECKeyGenerationParameters keyGenParam = new ECKeyGenerationParameters(ecParams, secureRandom);
    g.init(keyGenParam);
    pair = g.generateKeyPair();
    ECPrivateKeyParameters privatekeyparam = (ECPrivateKeyParameters)pair.getPrivate();
    ECPoint dd = secnamecurves.getG().multiply(privatekeyparam.getD());
    publickey = dd.getYCoord().toBigInteger().toByteArray();
  }
  
  public BigInteger[] signature(CipherParameters privatekey, byte[] input) throws GeneralSecurityException{

    ECDSASigner signer = new ECDSASigner();
    signer.init(true, privatekey);
    final BigInteger[] signature = signer.generateSignature(input);
    return signature;
  }


  public boolean verifySignature(CipherParameters publickey, byte[] input, BigInteger [] signature) throws GeneralSecurityException{

    ECDSASigner verifier = new ECDSASigner();
    verifier.init(false, publickey);
    boolean isVerified =verifier.verifySignature(input, signature[0], signature[1]);
    return isVerified;
  }

}
