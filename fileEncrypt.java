import java.io.*;
import java.security.KeyStore;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A script to encrypt and decrypt files using JCA. 
 * USAGE: java fileEncrypt 'file path' 'keystore password' 'operation'
 */

public class fileEncrypt {

    // Encryption or Decryption happens here depending upon the mode.
    private static byte[] operateOnFile(int mode, byte[] inputFile, SecretKeySpec key, IvParameterSpec iv) throws Exception {
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(mode, key, new IvParameterSpec(new byte[16]));

        byte[] output = cipher.doFinal(inputFile);
        System.out.println("Operation Completed");
        return output;
    }

    // Storing the generated key in the keystore.
    private static void storeInKeystore(SecretKeySpec toStore, char[] password, String alias, String path) throws Exception{

        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        File file = new File(path);

        // Checking if the keystore file exists. If it doesn't, creating a new one.
        if(!file.exists())
            keyStore.load(null, null);
        else{
            FileInputStream fis = new FileInputStream(file);
            keyStore.load(fis,password);
            fis.close();
        }

        System.out.println("KeyStore created");
        // Storing the key
        keyStore.setKeyEntry(alias, toStore, password, null);
        FileOutputStream fos = new FileOutputStream(path);
        keyStore.store(fos, password);
        System.out.println("Key stored");
    }

    // Getting the key to decrypt a file from the keystore.
    private static SecretKeySpec loadFromKeystore(char[] password, String alias, String path) throws Exception{
        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        FileInputStream fis = new FileInputStream(path);
        keyStore.load(fis, password);
        SecretKeySpec skey = (SecretKeySpec) keyStore.getKey(alias, password);
        keyStore.deleteEntry(alias);
        return skey;
    } 

    public static void main(String args[]) throws IOException, Exception {
        
        if(args.length != 2){
            System.err.println("Missing filepath or operation!");
            System.exit(1);
        }

        try{
            File file = new File(args[0]);
            
            Console cons = System.console();

            char[] password = cons.readPassword("[%s]", "Enter Password:");
            if(cons != null && password != null){
                System.out.println("Accepted");
            }
            String op = args[1];
            String filepath = "data.keystore";

            // Reading data into the inputFile byte Array.
            FileInputStream fis = new FileInputStream(file);
            byte[] inputFile = new byte[(int) file.length()];
            fis.read(inputFile);
            fis.close();

            // Generating an IV.
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            final IvParameterSpec iv = new IvParameterSpec(salt);

            FileOutputStream fos = new FileOutputStream(args[0]);

            if(op.equals("e")){
                // Generating random password to encrypt file.
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256);
                SecretKey skey = keyGen.generateKey();
                SecretKeySpec secretKey = new SecretKeySpec(skey.getEncoded(),"AES");

                // Storing the generated password in the KeyStore and encrypting the file.
                storeInKeystore(secretKey, password, args[0], filepath);
                byte[] encrypted = operateOnFile(1, inputFile, secretKey, iv);
                
                fos.write(encrypted);
                fos.close();
            }
            
            else if (op.equals("d")){
                // Retreiving password for given file and decrypting it.
                SecretKeySpec keyd = loadFromKeystore(password, args[0], filepath);
                byte[] decrypted = operateOnFile(2, inputFile, keyd, iv);

                fos.write(decrypted);
                fos.close();
            }

            else{
                System.out.println("Invalid Operation");
                fos.close();
            }
        }
        catch (Exception e){
            System.out.println("Operation failed.");
            e.printStackTrace();
        }
    }
}