/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package encryption;

/**
 *
 * @author timayabi
 */
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.*;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

class Encryption {

  public static void main(String[] args) {
   if (args.length != 1)
	System.out.println("Usage: RSAEncrypt nameOfFileToEncrypt");
   else
   try{

	Security.addProvider(new BouncyCastleProvider());
            /* Use existing keystore  */

	String ALIAS = "cellulant"; // keystore alias

	KeyStore keystore = KeyStore.getInstance("JKS");
	keystore.load(new FileInputStream("/srv/applications/UnifiedPayments/Keystore/nbc.jks"), null);
	X509Certificate cert = (X509Certificate)keystore.getCertificate(ALIAS);
	Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
	rsaCipher.init(Cipher.ENCRYPT_MODE, cert);


//------  Get the content data from file -------------
  File f = new File(args[0]) ;
  int sizecontent = ((int) f.length());
  byte[] data = new byte[sizecontent];

  try {
	FileInputStream freader = new FileInputStream(f);
	System.out.println("\nContent Bytes: " + freader.read(data, 0, sizecontent));
	freader.close();
	}
  catch(IOException ioe) {
	System.out.println(ioe.toString());
	return;
	}

	byte[] encrypteddata = rsaCipher.doFinal(data);
	Encryption.displayData(encrypteddata);
	/* Save the signature in a file */
	FileOutputStream sigfos = new FileOutputStream("rsaJencrypted");
	sigfos.write(encrypteddata);
	sigfos.close();
        }
  catch (Exception e) {
	System.err.println("Caught exception " + e.toString());
        }

    }
  private static void displayData(byte[] data)
  {
	System.out.println("Size of encrypted data: " + data.length) ;
	int bytecon = 0;    //to get unsigned byte representation
	for(int i=0; i<data.length ; i++){
		bytecon = data[i] & 0xFF ;   // byte-wise AND converts signed byte to unsigned.
           if(bytecon<16)
            System.out.print("0" + Integer.toHexString(bytecon).toUpperCase() + " ");   // pad on left if single hex digit.
            else
            System.out.print(Integer.toHexString(bytecon).toUpperCase() + " ");   // pad on left if single hex digit.
	  }
  }

}

