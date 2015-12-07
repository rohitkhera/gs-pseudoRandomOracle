/***********************************************************************
* FILENAME :        PseudoRandomOracle.java             
*
* DESCRIPTION :
*       A Controller to Implement a (pseudo) random oracle for the IND-CPA ciphertext distinguishing game
*
* PUBLIC FUNCTIONS :
*       
*
It is a standard approach to model modern ciphers as pseudo random functions (PRF). A PRF is semantically secure if knowledge of a cipher text does not reveal any information about the key or the plaintext to a **polynomial time** adversary (cf. contrast with "perfect secrecy"). An equivalent definition of sematic security is ciphertext indistinguishbility under chosen plaintext attack (IND-CPA security). This definition is based on a distinguishing game where a polynomial time adversary chooses two distinct messages, m_1 and m_2, and submits them to an encrypting oracle that implements the PRF. The oracle then randomly picks one of the two messages, encrypts them with the PRF, and returns this ciphertext to the adversary. The PRF is semantically secure if the likelihood that the adversary can correctly guess the corresponding plaintext to the ciphertext is no greater than 1/2 plus some "negligible" advantage

Implementation details: 
1) The chosen PRF is AES-128-CTR
2) Input plaintexts are each 16 bytes long which is equal to the AES block size
4) The two plaintexts are passed in to the rest endpoint through the following URL and parameter as a 64 character concatenated hex string:
http://pseudorandomoracle.cfapps.io/oracle?plaintexts=e0c10203f40501070d99aa0c00d0890fa0c13203f40501070d99aa0c00d089ff
    
5) The first 32 characters in the above parameter value correspond to the first 16 byte plaintext message and the second 32 characters correspond to the second 16 byte plaintext message sent by the adversary

* AUTHOR :    Rohit Khera        START DATE :    Dec. 6 2015
*
* CHANGES :
*  
* REF NO  VERSION DATE    WHO     DETAIL
* 
*
*/



package hello;

import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
 
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
 
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchProviderException;




public class PseudoRandomOracle {





    private final long id;
    private final String content;

    public PseudoRandomOracle(long id, String content) {
        this.id = id;
        this.content = content;
    }

    public long getId() {
        return id;
    }

    public String getContent() {
        return content;
    }

}
