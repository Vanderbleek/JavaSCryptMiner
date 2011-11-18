package com.dvanderbleek.miner;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.net.URLConnection;
import java.security.GeneralSecurityException;


import com.google.gson.Gson;
import com.lambdaworks.crypto.SCrypt;



public class Miner {

	/**
	 * @param args
	 * @throws GeneralSecurityException 
	 * @throws IOException 
	 */
	public static void main(String[] args) throws GeneralSecurityException, IOException {
		
		 final String rpcuser ="user"; //RPC User name (set in config)
		 final String rpcpassword ="x"; //RPC Pass (set in config)
		 
		  Authenticator.setDefault(new Authenticator() {//This sets the default authenticator, with the set username and password
		      protected PasswordAuthentication getPasswordAuthentication() {
		          return new PasswordAuthentication (rpcuser, rpcpassword.toCharArray());
		      }
		  });
		  while(true){
		  Work work = getwork(); //Gets the work from the server
		  String data = work.result.data; //Gets the data to hash from the work
		  String target = work.result.target;//Gets the target from the work
		  
		  //This chunk pulls apart the data so they can be endian switched (see the scrypt proof of work page on the wiki)
		  String version = data.substring(0, 8);
		  String prevhash = data.substring(8, 72);
		  String merkle = data.substring(72, 136 );
		  String timestamp = data.substring(136, 144);
		  String bits = data.substring(144, 152);
		  String nonce = data.substring(152,160);
		   
		  //This chunk creates endian switched byte arrays from the data
		   byte[] versionbit = chunkEndianSwitch(Converter.fromHexString(version));
		   byte[] prevhashbit = chunkEndianSwitch(Converter.fromHexString(prevhash));
		   byte[] merklebit = chunkEndianSwitch(Converter.fromHexString(merkle));
		   byte[] timestampbit = chunkEndianSwitch(Converter.fromHexString(timestamp));
		   byte[] bitsbit = chunkEndianSwitch(Converter.fromHexString(bits));
		   byte[] noncebit = chunkEndianSwitch(Converter.fromHexString(nonce));
		   
	       //This chunk of code reassembles the data into a single byre array      
		   byte[] databyte = new byte[80];
		   System.arraycopy(versionbit, 0, databyte, 0, versionbit.length);
		   System.arraycopy(prevhashbit, 0, databyte, 4, prevhashbit.length);
		   System.arraycopy(merklebit, 0, databyte, 36, merklebit.length);
		   System.arraycopy(timestampbit, 0, databyte, 68, timestampbit.length);
		   System.arraycopy(bitsbit, 0, databyte, 72, bitsbit.length);
		   System.arraycopy(noncebit, 0, databyte, 76, noncebit.length);
		   
		   //Converts the target string to a byte array for easier comparison
		   byte[] targetbyte = Converter.fromHexString(target);
		   targetbyte = endianSwitch(targetbyte);

		   byte[] scrypted = doScrypt(databyte, targetbyte);//Calls sCrypt with the proper parameters, and returns the correct data
		   byte[] databyte2 = Converter.fromHexString(data);
		   System.arraycopy(chunkEndianSwitch(scrypted), 0, databyte2, 76, scrypted.length);

		   work.result.data = printByteArray(databyte2);
		   System.out.println(sendWork(work));//Send the work
	}
	}
	
	public static byte[] doScrypt(byte[] databyte, byte[] target) throws GeneralSecurityException{
		//Initialize the nonce
		byte[] nonce = new byte[4];
		nonce[0] = databyte[76] ;
		nonce[1] = databyte[77] ;
		nonce[2] = databyte[78] ;
		nonce[3] = databyte[79] ;
		boolean found = false;
		//Loop over and increment nonce
		while(!found){
			//Set the bytes of the data to the nonce
			databyte[76] = nonce[0];
			databyte[77] = nonce[1];
			databyte[78] = nonce[2];
			databyte[79] = nonce[3];
			
			byte[] scrypted = (SCrypt.scryptJ(databyte,databyte, 1024, 1, 1, 32));//Scrypt the data with proper params
			
			BigInteger bigScrypt = new BigInteger(printByteArray(endianSwitch(scrypted)), 16); //Create a bigInteger to compare against the target
			BigInteger bigTarget = new BigInteger(printByteArray(target),16);//Create a bigInteger from the target 
			if(bigScrypt.compareTo(bigTarget) == -1){
				System.out.println(printByteArray(scrypted));
				return nonce;//Compare the two bigIntegers, return the data with nonce if smaller
			}
			
			else incrementAtIndex(nonce, nonce.length-1); //Otherwise increment the nonce
			
		}
		return nonce;
	}
	
	
	public  static void  incrementAtIndex(byte[] array, int index) {
		//Short method to increment the nonce
	    if (array[index] == Byte.MAX_VALUE) {
	        array[index] = 0;
	        if(index > 0)
	            incrementAtIndex(array, index - 1);
	    }
	    else {
	        array[index]++;
	    }
	}
	
	
	public static String prettyPrintByteArray(byte[] bites){
		//Method to convert a byte array to hex literal separated by bites.
		String str = "";
		int n = 0;
		for(byte bite:bites){
			n += 1;
			str = str + (Integer.toString( ( bite & 0xff ) + 0x100, 16 /* radix */ ).substring( 1 )) + " ";
			if((n%16) == 0) { str += "\n"; }
			else if((n%4) == 0) { str += " "; }
		}
		return str;
	}

	public static String printByteArray(byte[] bites){
		//Method to convert a byte array to hex literal
		String str = "";
		for(byte bite:bites){
			str = str + (Integer.toString( ( bite & 0xff ) + 0x100, 16 /* radix */ ).substring( 1 ));
		}
		return str;
	}
	
	public static byte[] endianSwitch(byte[] bytes) {
		//Method to switch the endianess of a byte array
	   byte[] bytes2 = new byte[bytes.length];
	   for(int i = 0; i < bytes.length;  i++){
		   bytes2[i] = bytes[bytes.length-i-1];
	   }
	   return bytes2;
	}

	public static byte[] chunkEndianSwitch(byte[] bytes) {
		//Method to properly switch the endianness of the header -- numbers must be treated as 32 bit chunks. Thanks to ali1234 for this.
	   byte[] bytes2 = new byte[bytes.length];
	   for(int i = 0; i < bytes.length;  i+=4){
		   bytes2[i] = bytes[i+3];
		   bytes2[i+1] = bytes[i+2];
		   bytes2[i+2] = bytes[i+1];
		   bytes2[i+3] = bytes[i];
	   }
	   return bytes2;
	}


	public static Work getwork() throws IOException{
		//Method to getwork
		URL url = new URL("http://127.0.0.1:9332");
	    URLConnection conn = url.openConnection();
	    conn.setDoOutput(true);
	    conn.setDoInput(true);
	    OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
	    String rpcreturn = "{\"jsonrpc\": \"1.0\" , \"method\": \"getwork\" }";//JSON RPC call for getting work
	    wr.write(rpcreturn);
	    wr.flush();
	    BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
	    String line;
	    
	    line = rd.readLine();
	    rd.close();
	    Gson gson = new Gson();
	    Work work = gson.fromJson(line, Work.class);//Use GSON to create a work object from the response
	    return work;  
	}

	public static String sendWork(Work work) throws IOException{
		//Very similar to getwork method
		URL url = new URL("http://127.0.0.1:9332");
	    URLConnection conn = url.openConnection();
	    conn.setDoOutput(true);
	    conn.setDoInput(true);
	    OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
	    System.out.println(work.result.data);
	    String rpcreturn = "{\"jsonrpc\": \"1.0\" , \"method\": \"getwork\" , \"params\" : [\"" +work.result.data+ "\"]}";//RPC call with the new nonced data
	    System.out.println(rpcreturn);
	    wr.write(rpcreturn);
	    wr.flush();
	    BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
	    String line;
	    line = rd.readLine();
	    rd.close();
	return line;
	}
}