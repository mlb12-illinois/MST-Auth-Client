package mst_auth_library;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.Builder;
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


//*******************************************************************
//*******************************************************************
//*******************************************************************
//
//This is the main MST-Auth Client Wrapper
//
//
// the main functions are:
//	CheckInboundHeader	- Inbound
//	BuildHeaders		- Outbound
//
//*******************************************************************
//*******************************************************************
//*******************************************************************

public class MST_Auth_ClientWrapper extends MST_Auth_BaseClientWrapper{
	private String encryptionlevel = "NONE";	// NONE BODY HEADER FULL
	private String mode = "SYNCH";	// OFFLINE ASYNCH SYNCH
	
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
	private String body_hash = null;	
	private UUID receiving_instanceid = null;
	private UUID receiving_serviceid = null;
	private Timestamp send_timestamp = null;
	private LinkedHashMap<String, JSONObject> graphname_to_auth = null;
	private LinkedHashMap<String, PublicKey> graphname_to_public = null;
	
	// object to log
	JSONObject logobject;	
	int reason_code;
	private int authflag = 0;

	protected MST_Auth_Servlet AuthReturn = null; // this is the hook to the servlet to get to "all things data with MST-Auth"
	

	public MST_Auth_ClientWrapper(MST_Auth_Utils parmMSTAUtils, MST_Auth_Servlet parmAuthReturn) {
		super(parmMSTAUtils);
		
		AuthReturn = parmAuthReturn;	// this is the hook to the servlet to get to "all things data with MST-Auth"
		
		// keep a copy of the hashmaps locally for the duration of this call
		// saves on updates from MST-Auth if we have to change the hashmaps
		try {
			MSTAUtils.listsemaphore.acquire();
			graphname_to_auth = new LinkedHashMap<>(MSTAUtils.graphname_to_auth);
			graphname_to_public = new LinkedHashMap<>(MSTAUtils.graphname_to_public);
			MSTAUtils.listsemaphore.release();
		} catch (Exception e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}
	}
	
	// *******************************************************************
	// *******************************************************************
	// *******************************************************************
	//
	//	Inbound Stuff
	//
	// *******************************************************************
	// *******************************************************************
	// *******************************************************************

	public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
	    //System.out.println(" auth client doGet :) ");
		InboundMethod = "GET";
		try {
			String decryptedbody = CheckInboundHeader(request);
			MST_Client.doGet(request, response, decryptedbody);			
		} catch (Exception e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}
		InboundMethod = null;
	}
	public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
		
		InboundMethod = "POST";
		try {
			String decryptedbody = CheckInboundHeader(request);
			MST_Client.doPost(request, response, decryptedbody);			
		} catch (Exception e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}			
		InboundMethod = null;
	}
	public void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
		
		InboundMethod = "PUT";
		try {
			String decryptedbody = CheckInboundHeader(request);
			MST_Client.doPut(request, response, decryptedbody);			
		} catch (Exception e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}			
		InboundMethod = null;
	}
	public void doDelete(HttpServletRequest request, HttpServletResponse response) throws IOException {
		
		InboundMethod = "DELETE";
		try {
			String decryptedbody = CheckInboundHeader(request);
			MST_Client.doDelete(request, response, decryptedbody);			
		} catch (Exception e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}			
		InboundMethod = null;
	}
	
	public void SetMicroservice(String microservicename) throws MSTAException {
		cleardata();
		
	    mstauthbuilder = HttpRequest.newBuilder();
		OutboundBody = "";
		OutboundService = microservicename;
		JSONObject GraphObject = graphname_to_auth.get(OutboundService);
		if (GraphObject == null)
	    	throw(new MSTAException (OutboundService + " Sent: within " + MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": Invalid input service"));		

		String GraphUID = GraphObject.getString("uri");
		
		//  $$$$$$$$$$$$$$$$$$$$$$$
		//if (OutboundService.equals("MSTABusiness")) GraphUID = "http://mstabusinessprocess-env.eba-ju2e6jsw.us-east-1.elasticbeanstalk.com/MSTA-BusinessService/MSTABusiness.html";
		//else if (OutboundService.equals("MSTAGateway")) GraphUID = "http://mstabusinessprocess-env.eba-ju2e6jsw.us-east-1.elasticbeanstalk.com/MSTA-Gateway/MSTAGateway.html";
		//else if (OutboundService.equals("MSTAAuthorization")) GraphUID = "http://mstabusinessprocess-env.eba-ju2e6jsw.us-east-1.elasticbeanstalk.com/MSTA-AuthorizationService/MSTAAuthorization.html";
		//else if (OutboundService.equals("MSTADataProvider")) GraphUID = "http://mstabusinessprocess-env.eba-ju2e6jsw.us-east-1.elasticbeanstalk.com/MSTA-DataProvider/MSTADataProvider.html";
		//if (OutboundService.equals("MSTABusiness")) GraphUID = "http://localhost:8080/MSTA-BusinessService/MSTABusiness.html";
		//else if (OutboundService.equals("MSTAGateway")) GraphUID = "http://localhost:8080/MSTA-Gateway/MSTAGateway.html";
		//else if (OutboundService.equals("MSTAAuthorization")) GraphUID = "http://localhost:8080/MSTA-AuthorizationService/MSTAAuthorization.html";
		//else if (OutboundService.equals("MSTADataProvider")) GraphUID = "http://localhost:8080/MSTA-DataProvider/MSTADataProvider.html";
		//if (OutboundService.equals("MSTABusiness")) GraphUID = "http://mstauth-env.eba-zgvgmydp.us-east-2.elasticbeanstalk.com/MSTA-BusinessService/MSTABusiness.html";
		//else if (OutboundService.equals("MSTAGateway")) GraphUID = "http://mstauth-env.eba-zgvgmydp.us-east-2.elasticbeanstalk.com/MSTA-Gateway/MSTAGateway.html";
		//else if (OutboundService.equals("MSTAAuthorization")) GraphUID = "http://mstauth-env.eba-zgvgmydp.us-east-2.elasticbeanstalk.com/MSTA-AuthorizationService/MSTAAuthorization.html";
		//else if (OutboundService.equals("MSTADataProvider")) GraphUID = "http://mstauth-env.eba-zgvgmydp.us-east-2.elasticbeanstalk.com/MSTA-DataProvider/MSTADataProvider.html";
		
		try {
				mstauthbuilder 
				.uri(new URI(GraphUID))
				.timeout(Duration.ofMillis(MSTAUtils.MSTA_RESPONSE_TIMEOUT));
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
	    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": Non MST-AUTH 1 rest calls not avalable"));		
		if ((MSTAUtils.CheckAuthorization(GraphObject, "SEND", method, InboundMethod) == 0)) {
			System.out.println("Throw1 method " + method + "inbound method " + InboundMethod + " " + GraphObject);
	    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": Invalid Send Authorization"));		
		}
		OutboundMethod = method;
		OutboundBody = new String(Base64.getEncoder().encode(body.getBytes()));;
	}
	
	public void SendRequestA() throws MSTAException {	
		try { 
;

			BuildHeaders();
			super.SendRequestA();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
	    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + e.toString()));		
		} 
		
	}

	public HttpResponse<String> SendRequest() throws MSTAException {	
		try {
		    System.out.println("SendRequest");
			BuildHeaders();
		    //System.out.println("BuildHeaders");
			HttpResponse<String> rsp = super.SendRequest();
		    System.out.println("EndRequest");
			return rsp;
		} catch (InvalidKeySpecException e) {
			e.printStackTrace(); 
	    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + e.toString()));		
		} 
	}

	// *******************************************************************
	//
	// check the header (all things MST-Auth receiving)
	//
	// *******************************************************************
	private String CheckInboundHeader(HttpServletRequest request) throws ServletException, MSTAException {
		String newbody = null;
		String mstaheader = null;
		try {
			NewMessageChain = 1;
			
			// see if there is a MST-AUTH header
			mstaheader = request.getHeader("MST-AUTH");
			if (mstaheader == null) {
				// no header, so from outside
				// set a flag for others
				//NewMessageChain = 1;
				// check to see if we can receive from outside
				JSONObject GraphObject = graphname_to_auth.get(MSTAUtils.microserviceName);
				if (GraphObject == null)
			    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": Non MST-AUTH 2 rest calls not avalable"));		
				if ((MSTAUtils.CheckAuthorization(GraphObject, "RECEIVE", "*", InboundMethod) == 0)) {
			    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": Non MST-AUTH 3 rest calls not avalable"));		
				}
				return null;
			}	
			else {
				// set a flag for others not a new chain
				NewMessageChain = 0;
				// there is a header
				// first things first, signature is required
				String graphensignature = request.getHeader("MST-AUTH-Signature");
			    //System.out.println("graphensignature Inbound: " + graphensignature);
				if (graphensignature == null) 
		    		throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": Non MST-AUTH 4 rest calls not avalable"));	
				

				
				byte[] signature = Base64.getDecoder().decode(graphensignature);
			
					newbody = request.getReader().lines().collect(Collectors.joining(System.lineSeparator()));
				    //System.out.println("OY0 New Body : " + newbody);
				    MessageDigest messageDigest;
				    messageDigest = MessageDigest.getInstance("SHA-256");
					//String hashstring = new String(mstaheader.getBytes()) + newbody;
					messageDigest.update(mstaheader.getBytes());
				    //messageDigest.update(mstaheader.getBytes());
				    String stringHash = new String(messageDigest.digest());
				    //System.out.println("Headaer Inbound: " + mstaheader);
				    //System.out.println("Hashed Inbound: " + stringHash);
				    
				    Signature sign;
				    X509EncodedKeySpec ks3 =  new X509EncodedKeySpec(MSTAUtils.decodepublic);
				    KeyFactory kf3 = KeyFactory.getInstance("RSA");
				    PublicKey publicKey = kf3.generatePublic(ks3);
				    sign = Signature.getInstance("SHA256withRSA");
					sign.initVerify(publicKey);
					sign.update(stringHash.getBytes(), 0, stringHash.getBytes().length );
					boolean verify = sign.verify(signature);
					//System.out.println("Signature " +  (verify ? "OK" : "Not OK"));	
					if (verify == false) throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": Invalid Signature"));	
					//if (verify == false) System.out.println("INVALID SIGNATURE " + MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": Invalid Signature");	
					//else System.out.println("OY SIG WORKED");
					
					// good signature
					// ok lets check encryption		
					String graphencryption = request.getHeader("MST-AUTH-Encryption");
					if (graphencryption == null) throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": Non MST-AUTH 5 rest calls not avalable"));
	
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
					    
					    byte[] decodedstr1 = (Base64.getDecoder().decode(newbody.getBytes()));
					    byte[] decodedstr2 = (Base64.getDecoder().decode(mstaheader.getBytes()));
					    
						if (graphencryptiontype.equals("BODY")) {
							newbody =  new String(encryptCipher.doFinal(decodedstr1));
							mstaheader =  new String(decodedstr2);						
						}
						else if (graphencryptiontype.equals("HEADER")) {
							newbody =  new String(decodedstr1);						
							mstaheader =  new String(encryptCipher.doFinal(decodedstr2));
						}
						else if (graphencryptiontype.equals("FULL")) {
							newbody =  new String(encryptCipher.doFinal(decodedstr1));						
							mstaheader =  new String(encryptCipher.doFinal(decodedstr2));
						} 
						else {
							newbody =  new String(decodedstr1);						
							mstaheader =  new String(decodedstr2);						
						}
				    }
	
				}
			    
				// good header (fully decrypted if encrypted)
				// can I receive from them?
		    	//System.out.println("mstaheader : " + mstaheader);
			    JSONObject jsonheader = new JSONObject(mstaheader);				
			    sending_servicename = jsonheader.getString("sending_servicename");
				String strUUID = jsonheader.getString("sending_instanceid");
				sending_instanceid = UUID.fromString(strUUID);
				strUUID = jsonheader.getString("sending_serviceid");
				sending_serviceid = UUID.fromString(strUUID);
				strUUID = jsonheader.getString("receiving_serviceid");
				receiving_serviceid = UUID.fromString(strUUID);
				receiving_servicename = jsonheader.getString("receiving_servicename");
				
				// did the body change
				MessageDigest messageDigest;
					//System.out.println("receive body length: " + newbody.length());
					messageDigest = MessageDigest.getInstance("SHA-256");
					String hashstring = new String(Base64.getEncoder().encode(newbody.getBytes()));
					messageDigest.update(hashstring.getBytes());
				    //System.out.println("OY1 out Body : " + OutboundBody);
					String stringHash = new String(messageDigest.digest() );
					body_hash = new String(Base64.getDecoder().decode(jsonheader.getString("body_hash"))); 
					if (!body_hash.equals(stringHash)) {
						System.out.println("header hash: " + body_hash + " body hash: " + stringHash);
				    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": Changed Body"));		
					}
				newbody = new String(Base64.getDecoder().decode(newbody.getBytes()));;
				
				// message tracking
				//System.out.println(mstaheader);
				strUUID = jsonheader.getString("msgid");
				msgid = UUID.fromString(strUUID);
				strUUID = jsonheader.getString("parent_msgid");
				parent_msgid = UUID.fromString(strUUID);
				strUUID = jsonheader.getString("root_msgid");
				root_msgid = UUID.fromString(strUUID);
				
			    if (!MSTAUtils.microserviceId.equals(receiving_serviceid.toString())) {
			    	System.out.println("wrong service id sent : " + mstaheader);
			    	System.out.println("MSTAUtils  MyMicroserviceName: " + MSTAUtils.microserviceName + " MSTAUtils  MyMicroserviceID: " + MSTAUtils.microserviceId);
			    	throw(new MSTAException (receiving_serviceid.toString() + " sent from: " + sending_servicename + " " + MSTAUtils.microserviceName + ": " + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": " + receiving_serviceid + " wrong service id sent"));
			    }
		    	if (!MSTAUtils.microserviceName.equals(receiving_servicename))  {
			    	System.out.println(" wrong service name sent : " + mstaheader);
			    	System.out.println("MSTAUtils  MyMicroserviceName: " + MSTAUtils.microserviceName + " MSTAUtils  MyMicroserviceID: " + MSTAUtils.microserviceId);
		    		throw(new MSTAException (sending_servicename + " sent to: " +  receiving_servicename + " - " + MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ":  wrong service name sent"));
		    	}
				// track receipt
			    Date date = new Date();
			    String timestamp = new Timestamp(date.getTime()).toString();	// use java.sql
			    jsonheader.put("receive_timestamp", timestamp);
			    jsonheader.put("log_timestamp", timestamp);
			    //jsonheader.put("receiving_serviceid", MyMicroserviceID);
			    jsonheader.put("receiving_instanceid", MSTAUtils.instanceId);
			    //jsonheader.put("receiving_servicename", MyMicroserviceName);
			    
		    	logobject = jsonheader;
		    	//logobject.put("receiving_instanceid", false);
				reason_code = 200;		

				//String jsonquery = "INSERT INTO mstauth.service_tree JSON '" + jsonheader.toString() +"'";
				//pServlet.CassandraInsert(jsonquery);
				
				// not a new chain so check auth
				if (NewMessageChain == 0 ) {
				    //System.out.println("Receive Header my name : " + MyMicroserviceName + " sender name: " + sending_servicename);
					JSONObject GraphObject = graphname_to_auth.get(sending_servicename);
					if (GraphObject == null)
				    	throw(new MSTAException (sending_servicename + " Invalid sender to: " + MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": Invalid sender"));		
					if ((MSTAUtils.CheckAuthorization(GraphObject, "RECEIVE", InboundMethod, InboundMethod) == 0)) {
				    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": Non MST-AUTH 6 rest calls not avalable"));
					}
			    	
			    }
				
				// anything else we want to do with the jsonheader put it here
				// OY
		} catch (InvalidKeyException e) {
			e.printStackTrace();
	    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": InvalidKeyException" + e));		
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
	    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": NoSuchAlgorithmException" + e));		
		} catch (SignatureException e) {
			e.printStackTrace();
	    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": SignatureException" + e));		
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
	    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": NoSuchPaddingException" + e));		
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
	    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": IllegalBlockSizeException" + e));		
		} catch (BadPaddingException e) {
			e.printStackTrace();
	    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": BadPaddingException" + e));		
		} catch (IOException e) {
			e.printStackTrace();
	    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": BadPaddingException" + e));		
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		finally {
			if (mstaheader != null) {
				mstauthbuilder = HttpRequest.newBuilder();
				if (logobject != null) {
					HttpRequest.Builder tempauthbuilder = mstauthbuilder;
					logobject.put("reason_code", reason_code);
					//logobject.remove("body_hash ");	// $$$ take out when zach adds this
					if ( authflag == 0 ) SendToAuth();	// flag will be put to 1 in SendToAuth so we don't loop
					mstauthbuilder = tempauthbuilder;
				}
			}
		}
		return newbody;
	}

	// *******************************************************************
	// *******************************************************************
	// *******************************************************************
	//
	//	Outbound Stuff
	//
	// *******************************************************************
	// *******************************************************************
	// *******************************************************************

	private void cleardata() {
		// ok so we allow services to send multiple rest calls
		// so we have to do a reset between calls
		
	
		//	InboundMethod = null; // invalid send auth - ok set at the beginning to POST in doPost etc. can't clean this one
		OutboundMethod = null;
		OutboundBody = null;
		OutboundService = null;	
		
		//  NewMessageChain = 1; // these are set in check hearder (only done once) do not reset
		//  root_msgid = null;
		//  parent_msgid = null;
		//	msgid = null;
		
		sending_servicename = null;	
		sending_instanceid = null;
		sending_serviceid = null;
		
		receiving_servicename = null;	
		body_hash = null;	
		receiving_instanceid = null;
		receiving_serviceid = null;
		send_timestamp = null;
		
	}
	
	// *******************************************************************
	//
	// build the headers (all things MST-Auth sending)
	//
	// *******************************************************************
	public void BuildHeaders() throws MSTAException, InvalidKeySpecException {
		try {
			// create header
			JSONObject newobj = new JSONObject();		
			newobj.put("sending_servicename", MSTAUtils.microserviceName);		
			newobj.put("sending_serviceid", MSTAUtils.microserviceId);
			newobj.put("sending_instanceid", MSTAUtils.instanceId);
			newobj.put("inbound_method", InboundMethod);
			newobj.put("outbound_method", OutboundMethod);
			//newobj.put("parent_msgid", msgid);
			//newobj.put("root_msgid", root_msgid);
		    Date date = new Date();
		    String timestamp = new Timestamp(date.getTime()).toString();	// use java.sql
			newobj.put("send_timestamp", timestamp);
			newobj.put("log_timestamp", timestamp);
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
			//msgid = UUID.randomUUID();
			//newobj.put("msgid", msgid);
			
			newobj.put("receiving_servicename", OutboundService); 
			JSONObject GraphObject = graphname_to_auth.get(OutboundService);
			String outinfo = GraphObject.getString("microserviceId");
			newobj.put("receiving_serviceid", outinfo);
			//newobj.put("receiving_instanceid", "");
			
			// hash the body pre encryption
			//System.out.println("sending body length: " + OutboundBody.length());
			//System.out.println("sending body: " + OutboundBody);
			
			MessageDigest messageDigest;

			messageDigest = MessageDigest.getInstance("SHA-256");
			String hashstring = new String(Base64.getEncoder().encode(OutboundBody.getBytes()));
			messageDigest.update(hashstring.getBytes());
		    //System.out.println("OY1 out Body : " + OutboundBody);
			String stringHash = new String(Base64.getEncoder().encode(messageDigest.digest()));
			newobj.put("body_hash", stringHash);
			
			logobject = newobj;
			reason_code = 200;		
	
			String newheader = newobj.toString();
			String graphencryption;
		    String sendSecret = "";
			
			PublicKey graphkey = graphname_to_public.get(OutboundService);
		    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");   
		    cipher.init(Cipher.ENCRYPT_MODE, graphkey); 
		    
			//JSONObject GraphObject = graphname_to_auth.get(OutboundService);

		    if (GraphObject != null ) {
		    	// $$$ back out
				//graphencryption = GraphObject.getString("GraphEncryption");
				graphencryption = encryptionlevel;
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
				    String teststring = new String(Base64.getEncoder().encode(rawData));
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
						
					    byte[] encodedoutarray2 = Base64.getEncoder().encode(newheader.getBytes());
					    newheader = new String(encodedoutarray2);						
					}
					else if (graphencryption.equals("HEADER")) {
					    byte[] outarray =  encryptCipher.doFinal(newheader.getBytes());
					    byte[] encodedoutarray = Base64.getEncoder().encode(outarray);
					    newheader = new String(encodedoutarray);
					    
					    byte[] encodedoutarray2 = Base64.getEncoder().encode(OutboundBody.getBytes());
						OutboundBody =  new String(encodedoutarray2);
					}
					else if (graphencryption.equals("FULL")) {
					    byte[] outarray =  encryptCipher.doFinal(OutboundBody.getBytes());
					    byte[] encodedoutarray = Base64.getEncoder().encode(outarray);
					    OutboundBody = new String(encodedoutarray);
						
					    byte[] outarray2 =  encryptCipher.doFinal(newheader.getBytes());
					    byte[] encodedoutarray2 = Base64.getEncoder().encode(outarray2);
					    newheader = new String(encodedoutarray2);
					}		
					else {
					    byte[] encodedoutarray = Base64.getEncoder().encode(OutboundBody.getBytes());
						OutboundBody =  new String(encodedoutarray);
						
					    byte[] encodedoutarray2 = Base64.getEncoder().encode(newheader.getBytes());
					    newheader = new String(encodedoutarray2);						
					}
		    	}		
		    }
		    else {
		    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": Build Header Invalid Arguments"));		
		    }

		    // sign this puppy
		    MessageDigest messageDigest2;

			messageDigest2 = MessageDigest.getInstance("SHA-256");
			messageDigest2.update(newheader.getBytes());
		    //System.out.println("OY1 out Body : " + OutboundBody);
			String stringHash2 = new String(messageDigest2.digest() );
			//System.out.println("OY0");
		    //System.out.println("Hashed Outbound: " + stringHash2);
			//System.out.println(stringHash.length());
		    //System.out.println("Headaer Outbound: " + newheader);
		    //System.out.println("Hashed Outbound: " + stringHash2);
	
			PKCS8EncodedKeySpec ks2 =  new PKCS8EncodedKeySpec(MSTAUtils.decryptedprivate);
		    KeyFactory kf2 = KeyFactory.getInstance("RSA");
		    PrivateKey privateKey = kf2.generatePrivate(ks2);
			Signature sign2 = Signature.getInstance("SHA256withRSA");
			sign2.initSign(privateKey);
			sign2.update(stringHash2.getBytes(), 0, stringHash2.getBytes().length );
			byte[] signature = sign2.sign();
			String s = new String(Base64.getEncoder().encode(signature));			  
			mstauthbuilder.header("MST-AUTH-Signature", s);		    
/*
		    X509EncodedKeySpec ks3 =  new X509EncodedKeySpec(MSTAUtils.decodepublic);
		    KeyFactory kf3 = KeyFactory.getInstance("RSA");
		    PublicKey publicKey = kf3.generatePublic(ks3);
		    Signature sign3 = Signature.getInstance("SHA256withRSA");
			sign3.initVerify(publicKey);
			sign3.update(stringHash2.getBytes(), 0, stringHash2.getBytes().length );
			boolean verify = sign3.verify(signature);	    
			if (verify == false) System.out.println("OY OY OY");	
*/		    
		
			// set the body
			//System.out.println("OY0 mstauthbuilder" );
			//System.out.println(OutboundBody);
			mstauthbuilder.method(OutboundMethod, HttpRequest.BodyPublishers.ofString(OutboundBody));		
			
		    // ADD the MST-AUTH header
			mstauthbuilder.header("MST-AUTH", newheader);
			JSONObject encobj = new JSONObject();		
			encobj.put("Encryption", graphencryption);
			encobj.put("Secret", sendSecret);
			//System.out.println("encrypted secret: " + encryptedSecret);
			String encheader = encobj.toString();
			mstauthbuilder.header("MST-AUTH-Encryption", encheader);
		    
	
		    //System.out.println(MyMicroserviceName + ": Setting Header");
			} catch (NoSuchAlgorithmException e) {
		    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": NoSuchAlgorithmException" + e));		
			} catch (NoSuchPaddingException e) {
				e.printStackTrace();
		    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": NoSuchPaddingException" + e));		
			} catch (InvalidKeyException e) {
				e.printStackTrace();
		    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": InvalidKeyException" + e));		
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
		    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": IllegalBlockSizeException" + e));		
			} catch (BadPaddingException e) {
				e.printStackTrace();
		    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": BadPaddingException" + e));		
			} catch (SignatureException e) {
				e.printStackTrace();
		    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + ": SignatureException" + e));		
			}
		finally {

			HttpRequest.Builder tempauthbuilder = mstauthbuilder;
			//mstauthbuilder = HttpRequest.newBuilder();	// don't need it here setmicroservice will do it, do need it on inbound
			logobject.put("reason_code", reason_code);
			//logobject.remove("body_hash ");
			if ( authflag == 0 ) SendToAuth();	// flag will be put to 1 in SendToAuth so we don't loop
			mstauthbuilder = tempauthbuilder;
		}
		
	}
	
	// *******************************************************************
	// *******************************************************************
	// *******************************************************************
	//
	//	Send to MST-Auth Server
	//
	// *******************************************************************
	// *******************************************************************
	// *******************************************************************

	private void SendToAuth() throws MSTAException {
		try {
			authflag = 1;
			if (mode.equals("NONE")) return;
			if (logobject == null) return;  // should not happen, but hey
			if (MSTAUtils.microserviceName.equals("MST_Auth")) return;	// we don't send to ourselves
	
			try {
			    if (mode.equals("ASYNCH2")) {	// ASYNCH Rest Call
					SetMicroservice("MST_Auth");		
					//System.out.println(MSTAUtils.GraphUID);
					SetMethodWithBodyString("POST", logobject.toString());
					SetHeader("Content-Type", "charset=UTF-8");				
					BuildHeaders();
			    	MST_Auth_SendThread T1 = new MST_Auth_SendThread(MSTAUtils, mstauthbuilder, AuthReturn);
			    	Thread t = new Thread (T1, "SendThread");					  
			        t.start();   	  
			    }
			    else if (mode.equals("ASYNCH")) {	// SYNCH websocket
					JSONObject newobj = new JSONObject();		
					newobj.put("event", logobject.toString());
					MST_Auth_SendThreadWS T1 = new MST_Auth_SendThreadWS(MSTAUtils, newobj, AuthReturn);
			    	Thread t = new Thread (T1, "SendThread");					  
			        t.start();   	  
					//newobj.put("Record", logobject.toString());		
					//System.out.println("newobject: " + newobj.toString());
					//String rsp = MSTAUtils.mylistener.SendMsg(newobj.toString(),  MSTAUtils.MSTA_RESPONSE_TIMEOUT);
					//System.out.println(rsp);
			    	//AuthReturn.AuthCallbackResponse(rsp);
			    }
			    else if (mode.equals("SYNCH")) {	// SYNCH websocket
					JSONObject newobj = new JSONObject();		
					newobj.put("event", logobject.toString());
					//newobj.put("Record", logobject.toString());		
					//System.out.println("newobject: " + newobj.toString());
					String rsp = MSTAUtils.mylistener.SendMsg(newobj.toString(),  MSTAUtils.MSTA_RESPONSE_TIMEOUT);
					//System.out.println(rsp);
			    	AuthReturn.AuthCallbackResponse(rsp);
			    }
			} catch (Exception e) {
				e.printStackTrace();
		    	throw(new MSTAException (MSTAUtils.microserviceName + ":" + MSTAUtils.microserviceId + ":" + MSTAUtils.instanceId + e.toString()));		
			} 
		}
		finally {
			authflag = 0;
		}
    	  
	}
	
	
}
