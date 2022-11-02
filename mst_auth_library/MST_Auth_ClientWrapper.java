package mst_auth_library;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.UUID;
import java.util.concurrent.Phaser;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONException;
import org.json.JSONObject;

import com.datastax.driver.core.SimpleStatement;
import com.datastax.driver.core.Statement;

import mst_auth_client.MST_Auth_Client;

public class MST_Auth_ClientWrapper extends MST_Auth_BaseClientWrapper{
	
	private MST_Auth_Servlet pServlet;
	private String InboundMethod = null;
	private String OutboundMethod = null;
	private String OutboundBody = null;
	private String OutboundService = null;	
	private int NewMessageChain;
	private UUID root_msgid = null;
	private UUID parent_msgid = null;
	private UUID msgid = null;
	private String sending_servicename = null;	
	private UUID sending_instanceid = null;
	private UUID sending_serviceid = null;
	private String receiving_servicename = null;	
	private UUID receiving_instanceid = null;
	private UUID receiving_serviceid = null;
	private Timestamp create_timestamp = null;
	private LinkedHashMap<String, JSONObject> graphname_to_auth = null;
	private LinkedHashMap<String, PublicKey> graphname_to_public = null;
	

	public MST_Auth_ClientWrapper(MST_Auth_Utils parmMSTAUtils, int parmMSTA_CONNECTION_TIMEOUT, int parmMSTA_RESPONSE_TIMEOUT, int parmMSTA_TIMEOUT_WAIT,  int parmMSTA_TRIES, MST_Auth_Servlet parampServlet) {
		super(parmMSTAUtils, parmMSTA_CONNECTION_TIMEOUT, parmMSTA_RESPONSE_TIMEOUT, parmMSTA_TIMEOUT_WAIT,  parmMSTA_TRIES);
		pServlet = parampServlet;
		graphname_to_auth = new LinkedHashMap<>(MSTAUtils.graphname_to_auth);
		graphname_to_public = new LinkedHashMap<>(MSTAUtils.graphname_to_public);
	}

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		InboundMethod = "GET";
	    mstauthbuilder = HttpRequest.newBuilder();
		try {
			String decryptedbody = CheckInboundHeader(request);
			MST_Client.doGet(request, response, decryptedbody);			
		} catch (IOException e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		} catch (MSTAException e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}			
		InboundMethod = null;
	}
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		InboundMethod = "POST";
		try {
			String decryptedbody = CheckInboundHeader(request);
			MST_Client.doPost(request, response, decryptedbody);			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		} catch (MSTAException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}			
		InboundMethod = null;
	}
	protected void doPut(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		InboundMethod = "PUT";
		try {
			String decryptedbody = CheckInboundHeader(request);
			MST_Client.doPut(request, response, decryptedbody);			
		} catch (IOException e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		} catch (MSTAException e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}			
		InboundMethod = null;
	}
	protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, InvalidKeySpecException {
		
		InboundMethod = "DELETE";
		try {
			String decryptedbody = CheckInboundHeader(request);
			MST_Client.doDelete(request, response, decryptedbody);			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		} catch (MSTAException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}			
		InboundMethod = null;
	}
	
	public void SetMicroservice(String microservicename) {
		
		OutboundBody = "";
		OutboundService = microservicename;
		JSONObject GraphObject = graphname_to_auth.get(OutboundService);
		MSTAUtils.GraphUID = GraphObject.getString("GraphURI");
	    System.out.println(MSTAUtils.MyMicroserviceName + OutboundService + " "+ MSTAUtils.GraphUID);
		
		try {
				mstauthbuilder 
				.uri(new URI(MSTAUtils.GraphUID))
				.timeout(Duration.ofMillis(MSTA_RESPONSE_TIMEOUT));
		} 
		catch (URISyntaxException e) {
			e.printStackTrace();
		}
		
	}
	
	public void SetMethodWithBodyString(String method, String body ) throws MSTAException {	
		// make sure this method is authorized
	    //System.out.println("SetMethodWithBodyString : " + MyMicroserviceName);
		JSONObject GraphObject = graphname_to_auth.get(OutboundService);
		if (GraphObject == null)
	    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": Non MST-AUTH rest calls not avalable"));		
		if ((MSTAUtils.CheckAuthorization(GraphObject, "SEND", method, InboundMethod) == 0)) {
	    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": Invalid Send Authorization"));		
		}
		OutboundMethod = method;
		OutboundBody = body;
	}
	
	public void SendRequestA() throws MSTAException {	
		try {
			BuildHeaders();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
	    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + e.toString()));		
		} 
		super.SendRequestA();
	}

	public HttpResponse<String> SendRequest() throws MSTAException {	
		try {
			BuildHeaders();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace(); 
	    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + e.toString()));		
		} 
		return super.SendRequest();
	}
	
	// *******************************************************************
	//
	// build the headers (all things MST-Auth sending)
	//
	// *******************************************************************
	public void BuildHeaders() throws MSTAException, InvalidKeySpecException {
		// create header
		JSONObject newobj = new JSONObject();		
		newobj.put("sending_servicename", MSTAUtils.MyMicroserviceName);		
		newobj.put("sending_serviceid", MSTAUtils.MyMicroserviceID);
		newobj.put("sending_instanceid", MSTAUtils.MyInstanceID);
		newobj.put("parent_msgid", msgid);
		newobj.put("root_msgid", root_msgid);
	    Date date = new Date();
	    String timestamp = new Timestamp(date.getTime()).toString();	// use java.sql
		newobj.put("create_timestamp", timestamp);
		UUID newmsgid = UUID.randomUUID();
		newobj.put("msgid", newmsgid);
		if (NewMessageChain == 1) {
			newobj.put("parent_msgid", newmsgid);
			newobj.put("root_msgid", newmsgid);			
			
		}
		else {
			newobj.put("parent_msgid", msgid);
			newobj.put("root_msgid", root_msgid);			
		}
		msgid = UUID.randomUUID();
		newobj.put("msgid", msgid);
		
		newobj.put("receiving_servicename", OutboundService); 
		JSONObject GraphObject = graphname_to_auth.get(OutboundService);
		String outinfo = GraphObject.getString("GraphID");
		newobj.put("receiving_serviceid", outinfo);
		//newobj.put("receiving_instanceid", "");
		
			String jsonquery = "INSERT INTO mstauth.service_tree JSON '" + newobj.toString() +"'";
			pServlet.CassandraInsert(jsonquery);
	

		String newheader = newobj.toString();
		String graphencryption;
	    String sendSecret = "";
		try {
		
			PublicKey graphkey = graphname_to_public.get(OutboundService);
		    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");   
		    cipher.init(Cipher.ENCRYPT_MODE, graphkey); 
		    
			//JSONObject GraphObject = graphname_to_auth.get(OutboundService);

		    if (GraphObject != null ) {
				graphencryption = GraphObject.getString("GraphEncryption");
				// default to no encryption
				if (graphencryption == null) {
					graphencryption = "NONE";
				}
				else if (!graphencryption.equals("NONE")) {
					// they want something encrypted
					// generate a temp secret key
			        SecureRandom securerandom = new SecureRandom();
					KeyGenerator  syncgenerator;
					syncgenerator = KeyGenerator.getInstance("AES");
					syncgenerator.init(256, securerandom);
				    SecretKey tempsecret = syncgenerator.generateKey();

				    // encrypt the temp secret with the receiving public
				    Cipher cipher6 = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");   
				    cipher6.init(Cipher.ENCRYPT_MODE, graphkey); 				    
				    byte[] rawData = tempsecret.getEncoded();
				    String teststring = Base64.getEncoder().encodeToString(rawData);
				    //System.out.println("OY666 : " + teststring);
				    byte[] testarray =  cipher6.doFinal(teststring.getBytes());
				    //System.out.println(testarray.length);
				    byte[] encodedtestarray = Base64.getEncoder().encode(testarray);
				    sendSecret = new String(encodedtestarray);

				    // encrypt stuff with temp secret
				    Cipher encryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
				    encryptCipher.init(Cipher.ENCRYPT_MODE, tempsecret);
				    
					if (graphencryption.equals("BODY")) {
					    byte[] outarray =  encryptCipher.doFinal(OutboundBody.getBytes());
					    byte[] encodedoutarray = Base64.getEncoder().encode(outarray);
						OutboundBody =  new String(encodedoutarray);
					}
					else if (graphencryption.equals("HEADER")) {
					    byte[] outarray =  encryptCipher.doFinal(newheader.getBytes());
					    byte[] encodedoutarray = Base64.getEncoder().encode(outarray);
					    newheader = new String(encodedoutarray);
					}
					if (graphencryption.equals("FULL")) {
					    byte[] outarray =  encryptCipher.doFinal(OutboundBody.getBytes());
					    byte[] encodedoutarray = Base64.getEncoder().encode(outarray);
					    OutboundBody = new String(encodedoutarray);
						
					    byte[] outarray2 =  encryptCipher.doFinal(newheader.getBytes());
					    byte[] encodedoutarray2 = Base64.getEncoder().encode(outarray2);
					    newheader = new String(encodedoutarray2);
					}					
		    	}		
		    }
		    else {
		    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": Build Header Invalid Arguments"));		
		    }
		} catch (NoSuchAlgorithmException e) {
	    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": NoSuchAlgorithmException" + e));		
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
	    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": NoSuchPaddingException" + e));		
		} catch (InvalidKeyException e) {
			e.printStackTrace();
	    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": InvalidKeyException" + e));		
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
	    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": IllegalBlockSizeException" + e));		
		} catch (BadPaddingException e) {
			e.printStackTrace();
	    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": BadPaddingException" + e));		
		}
		
		// set the body
		mstauthbuilder.method(OutboundMethod, HttpRequest.BodyPublishers.ofString(OutboundBody));		
		
	    // ADD the MST-AUTH header
		mstauthbuilder.header("MST-AUTH", newheader);
		JSONObject encobj = new JSONObject();		
		encobj.put("Encryption", graphencryption);
		encobj.put("Secret", sendSecret);
		//System.out.println("encrypted secret: " + encryptedSecret);
		String encheader = encobj.toString();
		mstauthbuilder.header("MST-AUTH-Encryption", encheader);
	    
	    // sign this puppy
		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance("SHA-256");
			messageDigest.update(newheader.getBytes());
			String stringHash = new String(messageDigest.digest());
			//System.out.println("OY0");
			//System.out.println(stringHash);
			//System.out.println(stringHash.length());
	
			PKCS8EncodedKeySpec ks2 =  new PKCS8EncodedKeySpec(MSTAUtils.decryptedprivate);
		    KeyFactory kf2 = KeyFactory.getInstance("RSA");
		    PrivateKey privateKey = kf2.generatePrivate(ks2);
			Signature sign = Signature.getInstance("SHA256withRSA");
			sign.initSign((java.security.PrivateKey) privateKey);
			sign.update(stringHash.getBytes(), 0,stringHash.length() );
			byte[] signature = sign.sign();
			String s = Base64.getEncoder().encodeToString(signature);			  
			mstauthbuilder.header("MST-AUTH-Signature", s);
		    
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
	    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": NoSuchAlgorithmException" + e));		
		} catch (InvalidKeyException e) {
			e.printStackTrace();
	    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": InvalidKeyException" + e));		
		} catch (SignatureException e) {
			e.printStackTrace();
	    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": SignatureException" + e));		
		}

	    //System.out.println(MyMicroserviceName + ": Setting Header");
		
	}
	// *******************************************************************
	//
	// check the header (all things MST-Auth receiving)
	//
	// *******************************************************************
	private String CheckInboundHeader(HttpServletRequest request) throws MSTAException, ServletException, InvalidKeySpecException {
		NewMessageChain = 0;
		// lets get the body
		StringBuffer jb = new StringBuffer();
		String line = null;
		try {
			BufferedReader reader = request.getReader();
			// we need to reset in case the program wants to do something special
			reader.mark(Integer.MAX_VALUE);
			while ((line = reader.readLine()) != null)
				jb.append(line);
			reader.reset();
		} 
		catch (IOException e) { 
	    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": Invalid Signature"));		
		}
	  	String newbody = jb.toString();
		
		// see if there is a MST-AUTH header
		String mstaheader = request.getHeader("MST-AUTH");
		if (mstaheader == null) {
			// no header, so from outside
			// set a flag for others
			NewMessageChain = 1;
			// check to see if we can receive from outside
			JSONObject GraphObject = graphname_to_auth.get(MSTAUtils.MyMicroserviceName);
			if (GraphObject == null)
		    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": Non MST-AUTH rest calls not avalable"));		
			if ((MSTAUtils.CheckAuthorization(GraphObject, "RECEIVE", "*", InboundMethod) == 0)) {
				//System.out.println("Throw1");
		    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": Non MST-AUTH rest calls not avalable"));		
			}
		}	
		else {
			// there is a header
			// first things first, signature is required
			String graphensignature = request.getHeader("MST-AUTH-Signature");
			if (graphensignature == null) 
	    		throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": Non MST-AUTH rest calls not avalable"));		
		    byte[] signature = Base64.getDecoder().decode(graphensignature);
		
		    try {
			    MessageDigest messageDigest;
			    messageDigest = MessageDigest.getInstance("SHA-256");
			    messageDigest.update(mstaheader.getBytes());
			    String stringHash = new String(messageDigest.digest());
			  
			    Signature sign;
			    X509EncodedKeySpec ks3 =  new X509EncodedKeySpec(MSTAUtils.decodepublic);
			    KeyFactory kf3 = KeyFactory.getInstance("RSA");
			    PublicKey publicKey = kf3.generatePublic(ks3);
			    sign = Signature.getInstance("SHA256withRSA");
				sign.initVerify((PublicKey) publicKey);
				sign.update(stringHash.getBytes(), 0, stringHash.getBytes().length );
				boolean verify = sign.verify(signature);
				//System.out.println("Signature " +  (verify ? "OK" : "Not OK"));	
				if (verify == false) throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": Invalid Signature"));	
				
				// good signature
				// ok lets check encryption			
				String graphencryption = request.getHeader("MST-AUTH-Encryption");
				if (graphencryption == null) throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": Non MST-AUTH rest calls not avalable"));

				//  get the encryption type from the header
		    	JSONObject jsonenc =  new JSONObject(graphencryption);
				byte[] jsonsecret = jsonenc.getString("Secret").getBytes();			    
			    byte[] decodedsecret = (Base64.getDecoder().decode(jsonsecret));
			    
			    String graphencryptiontype = jsonenc.getString("Encryption");	    
				if (!graphencryptiontype.equals("NONE")) {
					// something to decrypt
					// decrypt the temp secret
					PKCS8EncodedKeySpec ks2 =  new PKCS8EncodedKeySpec(MSTAUtils.decryptedprivate);
				    KeyFactory kf2 = KeyFactory.getInstance("RSA");
				    PrivateKey privateKey = kf2.generatePrivate(ks2);
				    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");   
				    cipher.init(Cipher.DECRYPT_MODE, privateKey);
				    String strsecret =  new String(cipher.doFinal(decodedsecret));
				    byte[] decodedKey = Base64.getDecoder().decode(strsecret);
				    
				    // create the temp cipher
				    SecretKey msgsecret = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
				    Cipher encryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
				    encryptCipher.init(Cipher.DECRYPT_MODE, (msgsecret));

					if (graphencryptiontype.equals("BODY")) {
						byte[] encodedstr = newbody.getBytes();			    
					    byte[] decodedstr = (Base64.getDecoder().decode(encodedstr));
						newbody =  new String(encryptCipher.doFinal(decodedstr));
					}
					else if (graphencryptiontype.equals("HEADER")) {
						byte[] encodedstr = mstaheader.getBytes();			    
					    byte[] decodedstr = (Base64.getDecoder().decode(encodedstr));
						mstaheader =  new String(encryptCipher.doFinal(decodedstr));
					}
					else if (graphencryptiontype.equals("FULL")) {
						byte[] encodedstr = newbody.getBytes();			    
					    byte[] decodedstr = (Base64.getDecoder().decode(encodedstr));
						newbody =  new String(encryptCipher.doFinal(decodedstr));
						
						byte[] encodedstr2 = mstaheader.getBytes();			    
					    byte[] decodedstr2 = (Base64.getDecoder().decode(encodedstr2));
						mstaheader =  new String(encryptCipher.doFinal(decodedstr2));
					} 
			    }

			} catch (InvalidKeyException e) {
				e.printStackTrace();
		    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": InvalidKeyException" + e));		
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
		    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": NoSuchAlgorithmException" + e));		
			} catch (SignatureException e) {
				e.printStackTrace();
		    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": SignatureException" + e));		
			} catch (NoSuchPaddingException e) {
				e.printStackTrace();
		    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": NoSuchPaddingException" + e));		
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
		    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": IllegalBlockSizeException" + e));		
			} catch (BadPaddingException e) {
				e.printStackTrace();
		    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": BadPaddingException" + e));		
			}
			
		    
			// good header (fully decrypted if encrypted)
			// can I receive from them?
		    JSONObject jsonheader = new JSONObject(mstaheader);	
			
			
		    sending_servicename = jsonheader.getString("sending_servicename");
			String strUUID = jsonheader.getString("sending_instanceid");
			sending_instanceid = UUID.fromString(strUUID);
			strUUID = jsonheader.getString("sending_serviceid");
			sending_serviceid = UUID.fromString(strUUID);
			strUUID = jsonheader.getString("receiving_serviceid");
			receiving_serviceid = UUID.fromString(strUUID);
			receiving_servicename = jsonheader.getString("receiving_servicename");
			
			// message tracking
			strUUID = jsonheader.getString("msgid");
			msgid = UUID.fromString(strUUID);
			strUUID = jsonheader.getString("parent_msgid");
			parent_msgid = UUID.fromString(strUUID);
			strUUID = jsonheader.getString("root_msgid");
			root_msgid = UUID.fromString(strUUID);
			
			String strTime = jsonheader.getString("create_timestamp");			
			create_timestamp = Timestamp.valueOf(strTime);

		    if (!MSTAUtils.MyMicroserviceID.equals(receiving_serviceid.toString()))
		    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": " + receiving_serviceid + " wrong service id sent"));
		    if (!MSTAUtils.MyMicroserviceName.equals(receiving_servicename)) 
		    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": " + receiving_servicename + " wrong service name sent"));

			// track receipt
		    Date date = new Date();
		    String timestamp = new Timestamp(date.getTime()).toString();	// use java.sql
		    jsonheader.put("create_timestamp", timestamp);
		    //jsonheader.put("receiving_serviceid", MyMicroserviceID);
		    jsonheader.put("receiving_instanceid", MSTAUtils.MyInstanceID);
		    //jsonheader.put("receiving_servicename", MyMicroserviceName);
		    
				String jsonquery = "INSERT INTO mstauth.service_tree JSON '" + jsonheader.toString() +"'";
				pServlet.CassandraInsert(jsonquery);
				
				// not a new chain so check auth
				if (NewMessageChain == 0 ) {
				    //System.out.println("Receive Header my name : " + MyMicroserviceName + " sender name: " + sending_servicename);
					JSONObject GraphObject = graphname_to_auth.get(sending_servicename);
					if (GraphObject == null)
				    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": Non MST-AUTH rest calls not avalable"));		
					if ((MSTAUtils.CheckAuthorization(GraphObject, "RECEIVE", InboundMethod, InboundMethod) == 0)) {
				    	throw(new MSTAException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": Non MST-AUTH rest calls not avalable"));
					}
		    	
		    }
			
			// anything else we want to do with the jsonheader put it here
			// OY
		}
		return newbody;
	}
	
}
