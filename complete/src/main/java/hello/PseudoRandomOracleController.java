/***********************************************************************
* FILENAME :        PseudoRandomOracleController.java             
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

import java.util.concurrent.atomic.AtomicLong;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PseudoRandomOracleController {


    private static final String template= "the first plaintext is ";

    private final AtomicLong counter = new AtomicLong();

    @RequestMapping("/oracle")
    public PseudoRandomOracle  oracle(@RequestParam(value="plaintexts", defaultValue="none") String plaintexts) {


	/*
	StringBuffer buf=new StringBuffer();
	buf.append(template);
	buf.append(" ");
	buf.append(plaintexts.length());
        return new PseudoRandomOracle(counter.incrementAndGet(),
				      String.format(buf.toString(), plaintexts));


	*/
	StringBuffer buf = new StringBuffer();
	if(plaintexts.length()!=64) {
	    buf.append("Please provide a string of 64 hexadecimal characters representing two plaintexts of length 16 bytes. A valid sample invocation of this endpoint is  http://pseudorandomoracle.cfapps.io/oracle?plaintexts=70c10203f40501070d99aa0c00d0890fa0c13203f40501070d99aa0c00d089ff (You can change any one of the nibbles or bytes within the 64 char string associated with the URL parameter plaintexts). ");
	    buf.append("This service implements a random oracle for a ciphertext distinguishing game on PWS. ");
	    buf.append("The point of this game is to demonstrate ciphertext indistinguishiiblity of the AES-128-CTR pseudo random function (PRF) under chosen plaintext attack (i.e. IND-CPA security). This is equivalent to demonstrating semantic security of the AES-128-CTR PRF");  
            return new PseudoRandomOracle(counter.incrementAndGet(), buf.toString());
	}
	else {
	    PseudoRandomOracleHelper helper = new PseudoRandomOracleHelper(plaintexts);

	    buf.append("Welcome to Rohit's random oracle for a ciphertext distinguishing game on PWS. ");
	    buf.append("The point of this game is to demonstrate ciphertext indistinguishiiblity of the AES-128-CTR pseudo random function (PRF) under chosen plaintext attack (i.e. IND-CPA security). This is equivalent to demonstrating semantic security of the AES-128-CTR PRF. (You can change any one of the nibbles or bytes within the 64 char string associated with the URL parameter plaintexts).");  
	    buf.append(" You sent me two plaintexts: ");
	    buf.append(helper.getPlaintext1());
	    buf.append(" and: ");
	    buf.append(helper.getPlaintext2());
	    buf.append(". I encrypted one of them to produce the ciphertext: ");
	    buf.append(helper.getCipherText());
	    buf.append(". Can you guess which plaintext I encrypted with probability significantly greater than 1/2? ");
	    return new PseudoRandomOracle(counter.incrementAndGet(), String.format(buf.toString()));
	}


    }
}
