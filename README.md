# Encrypt

A script that can encrypt and decrypt files passed in through the command line.

It implements the AES algorithm with the help of classes from the Java Cryptography Architecture. For each new file, a random key is generated which is then used to encrypt it. The key is stored in a `KeyStore`, with the file name. During decryption, this key is retrieved and then deleted to allow for the storage of another random key if the same file needs to be encrypted.

Only a password for the KeyStore is required when executing the script.

# Usage

First, compile the .java file by executing `javac fileEncrypt.java`

Three parameters are expected : file path, password for the keystore, and type of operation (`e` for encryption and `d` for decryption). Which results in :
`java fileEncrypt 'path to file' 'keystore password' 'operation'`
