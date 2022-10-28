package mst_auth_library;

import mst_auth_client.MST_Auth_Client;

import java.io.BufferedReader;
//import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
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
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.print.DocFlavor.URL;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * mst_auth_servlet is the client side library for the MST-Auth platform
 * 
 * Implements (forwards to the client class):
 * 	  init
 *    doGet
 *    doPut
 *    doPost
 *    doDelete
 * 
 * @author mlbernardoni
 *
 */

/**
 * Servlet implementation class mst_auth_servlet
 */
@WebServlet("/MST_Auth_Servlet")
public class MST_Auth_Servlet extends HttpServlet {
	private int RESTOREPROPERTYDEFAULTS = 0;
	// parameters either from properties, MSTAConfiguration.json or from MST-Auth Register
	private int MSTA_DO_INIT;
	private int MSTA_CONNECTION_TIMEOUT;
	private int MSTA_RESPONSE_TIMEOUT;
	private int MSTA_TIMEOUT_WAIT;
	private int MSTA_TRIES;
	private String MSTA_URL;
	private String GraphUID;
	//private String GraphName;
	private String MyMicroserviceName;
	private String MyMicroserviceID;
	private String MyInstanceID;
	private String MyURI;
	private String MyHash;
	private String MyPublic;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private SecretKey secretKey;
	
	//
	//the in memory hash map of all things MST-AUTH
	private LinkedHashMap<String, JSONObject> graphname_to_auth;
	private LinkedHashMap<String, PublicKey> graphname_to_public;
	
	// variables used while processing rest calls
	private String InboundMethod;
	private String OutboundMethod;
	private String OutboundBody;
	private String GraphName;
	
	private MST_Auth_Client MST_Client;
	private HttpRequest.Builder mstauthbuilder;
	private HttpServletResponse myresponse;
	public JSONObject inputjson;
	
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public MST_Auth_Servlet() {
        super();
    }

	/**
	 * @see Servlet#init(ServletConfig)
	 */
	// *******************************************************************
	//
    // init
    //
    // create client
    //
	// get config 
	//		from webapp directory (in summary we need at least (1) MSTA_URL or (2) everything (including DO_INIT set to 0)
	//
	//		if registration is not required we get everything from MSTAConfiguration.json
	//      else we get it all from the AUTH-Server register
	//
	// AS WE ADD PARAMETERS
	//		ADD TO CLASS VARIABLE ABOVE
	//		NEED TO ADD IT HERE BOTH TO CACHE AND REGISTER
	//		AND INTO THE MSTAConfiguration.json FOR EACH SERVICE
    //
    //		AND DELETE THE PROPERTY FILE HERE (the program will recreate this file from MSTAConfiguration.json
    //      ...eclipse-workspace\.metadata\.plugins\org.eclipse.wst.server.core\tmp0\wtpwebapps\MSTA-Builder\WEB-INF\classes
    //		you can do this by setting the first variable RESTOREPROPERTYDEFAULTS to 1 (don't forget to reset it after)
	//
	// *******************************************************************
	public void init(ServletConfig config) throws ServletException {
		//
		// initialize some variables
		//
		GraphName = "";
		InboundMethod = "";
		OutboundMethod = "";
		OutboundBody = "";
		secretKey = null;
		graphname_to_auth = new LinkedHashMap<String, JSONObject>();
		graphname_to_public = new LinkedHashMap<String, PublicKey>();
		
		// create the client
		// create the linkage for client back to us
		MST_Client = new MST_Auth_Client();
		MST_Client.SetLibrary(this);
		
		//
		// first we try and get config from properties
		// if not there, we get from default properties
		//
		ClassLoader classLoader = Thread.currentThread().getContextClassLoader();     
	    String rootPath = classLoader.getResource("").getPath();
	    String appConfigPath = rootPath + "MST-Auth.properties";
	    //System.out.println("path: " + appConfigPath);
	    Properties mstaproperties = new Properties();
	    String strproperties = "";
	    try {
	    	FileInputStream fis = new FileInputStream(appConfigPath);
		    mstaproperties.load(fis);
		    strproperties = mstaproperties.getProperty("MST-Auth", "defaultName");
		    //System.out.println("stored prop: " + strproperties);
		    fis.close();
		    
		    // at built time, we can delete a property file here
		    if (RESTOREPROPERTYDEFAULTS == 1) {
		    	strproperties = "";	
		    	 File f1 = new File(appConfigPath); 
		    	 boolean success=f1.delete();
		    	 if(!success){
		 		    System.out.println("OY Restore Property Defaults did NOT work");
		    	 }
		    	 else {
			 		System.out.println("OY Restore Property Defaults DID work");
			    	throw(new IOException ("RELOAD PROPERTY AFTER DELETE"));
		    	 }
	    	 }

	    } catch (IOException  e) {
	    	// TODO Auto-generated catch block
		    System.out.println("property not found load from default");		    	
			// get the json string from the WEB-INF directory			
			InputStream stream = classLoader.getResourceAsStream("../MSTAConfiguration.json");
		    //System.out.println(stream);
			if (stream == null) {
			    System.out.println("MSTAConfiguration.json missing from WEB-INF folder");
		    	throw(new NullPointerException ("MSTAConfiguration.json missing from WEB-INF folder"));		
			}
			ByteArrayOutputStream result = new ByteArrayOutputStream();
			byte[] buffer = new byte[2048];
			try {
				for (int length; (length = stream.read(buffer)) != -1; ) {
				     result.write(buffer, 0, length);
				}
				strproperties = result.toString("UTF-8");
				
				// store in properties
			    mstaproperties.setProperty("MST-Auth", strproperties); // update an old value
			    mstaproperties.store(new FileWriter(appConfigPath), "store to properties file");
			} catch (IOException e1) {
			    System.out.println("MSTAConfiguration.json missing from WEB-INF folder");
		    	throw(new NullPointerException ("MSTAConfiguration.json missing from WEB-INF folder"));		
			}
	    }

		// we now have config in strproperties
		try {
			//
			JSONObject r2sconifg =  new JSONObject(strproperties);
			inputjson = r2sconifg;
			
			// MSTA_URL is required if MSTA_DO_INIT is not 0
			int URL_REQUIRED = 1;
			if(r2sconifg.has("MSTA_DO_INIT")) {
				MSTA_DO_INIT = r2sconifg.getInt("MSTA_DO_INIT");
				if (MSTA_DO_INIT == 0) 
					URL_REQUIRED = 0;
			}
			if(r2sconifg.has("MSTA_URL"))
				MSTA_URL = r2sconifg.getString("MSTA_URL");
			else {
				if (URL_REQUIRED == 1) {
				    System.out.println(MyMicroserviceName + "MSTA_URL missing MSTAConfiguration.json in WEB-INF folder");
			    	throw(new NullPointerException (MyMicroserviceName + "MSTA_URL missing MSTAConfiguration.json in WEB-INF folder"));		
				}
			}
			//
			// we need cache if not from MST-AUTH server
			//
			if (URL_REQUIRED != 1) {	
				int invalidconfig = 0;
				if(!r2sconifg.has("MSTA_CONNECTION_TIMEOUT")) invalidconfig = 1; else
					MSTA_CONNECTION_TIMEOUT = r2sconifg.getInt("MSTA_CONNECTION_TIMEOUT");
				if(!r2sconifg.has("MSTA_RESPONSE_TIMEOUT")) invalidconfig = 1; else
					MSTA_RESPONSE_TIMEOUT = r2sconifg.getInt("MSTA_RESPONSE_TIMEOUT");
				if(!r2sconifg.has("MSTA_TIMEOUT_WAIT")) invalidconfig = 1; else
					MSTA_TIMEOUT_WAIT = r2sconifg.getInt("MSTA_TIMEOUT_WAIT");
				if(!r2sconifg.has("MSTA_TRIES")) invalidconfig = 1; else
					MSTA_TRIES = r2sconifg.getInt("MSTA_TRIES");
				if(!r2sconifg.has("MyMicroserviceName")) invalidconfig = 1; else
					MyMicroserviceName = r2sconifg.getString("MyMicroserviceName");
				System.out.println(MyMicroserviceName);
				if(!r2sconifg.has("MyMicroserviceID")) invalidconfig = 1; else
					MyMicroserviceID = r2sconifg.getString("MyMicroserviceID");
				if(!r2sconifg.has("MyURI")) invalidconfig = 1; else
					MyURI = r2sconifg.getString("MyURI");
				if(!r2sconifg.has("MyPublic")) invalidconfig = 1; else
					MyPublic = r2sconifg.getString("MyPublic");
				if(!r2sconifg.has("MicroserviceGraph")) invalidconfig = 1; else {
				    JSONArray  jsonms = r2sconifg.getJSONArray("MicroserviceGraph");
				    KeyFactory kfinit = KeyFactory.getInstance("RSA");
				    for (int i = 0; i < jsonms.length(); i++) { 
				    	 JSONObject GraphObject = jsonms.getJSONObject(i);  
				    	 String graphname = GraphObject.getString("GraphName");
				    	 graphname_to_auth.put(graphname, GraphObject);

				    	String graphpublic = GraphObject.getString("GraphPublic");
					    byte[] decodepublic = Base64.getDecoder().decode(graphpublic);		    
					    X509EncodedKeySpec ks3 =  new X509EncodedKeySpec(decodepublic);
					    PublicKey graphKey = kfinit.generatePublic(ks3);
					    graphname_to_public.put(graphname, graphKey);			    
				    }
				}
				
				// *****************************************************
			    // REMOVE WHEN WE HAVE MST-Auth and Register
				//
				if(!r2sconifg.has("MyHash")) invalidconfig = 1; else
				{
					MyHash = r2sconifg.getString("MyHash");
				    byte[] decodesecret = Base64.getDecoder().decode(MyHash);		    
				    secretKey = new SecretKeySpec(decodesecret, 0, decodesecret.length, "AES"); 
				}
				
			    //System.out.println(MyMicroserviceName);
				/* took to long to do this, lets save it for a while
			    InputStream stream1 = classLoader.getResourceAsStream("../publicKey.key");
			    //System.out.println(stream1);
				if (stream1 == null) {
				    System.out.println("publicKey missing from WEB-INF folder");
			    	throw(new NullPointerException (MyMicroserviceName + "MSTAConfiguration.json missing from WEB-INF folder"));		
				}
			    ObjectInputStream oin1 = new ObjectInputStream(stream1);
			    publicKey = (PublicKey) oin1.readObject();
				oin1.close();
				stream1.close();
				*/
				//System.out.println("MyPublic : " + MyPublic);
			    byte[] decodepublic = Base64.getDecoder().decode(MyPublic);		    
			    X509EncodedKeySpec ks3 =  new X509EncodedKeySpec(decodepublic);
			    KeyFactory kf3 = KeyFactory.getInstance("RSA");
			    publicKey = kf3.generatePublic(ks3);
				
				
			    InputStream stream2 = classLoader.getResourceAsStream("../privateKey.key");
			    //System.out.println(stream2);
				if (stream2 == null) {
				    System.out.println("privateKey missing from WEB-INF folder");
			    	throw(new NullPointerException (MyMicroserviceName + "MSTAConfiguration.json missing from WEB-INF folder"));		
				}
				ObjectInputStream oin2 = new ObjectInputStream(stream2);
			    byte[] loadedprivate = (byte[]) oin2.readObject();
			    oin2.close();
			    stream2.close();

				// decrypt it
			    Cipher encryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			    encryptCipher.init(Cipher.DECRYPT_MODE, secretKey);
			    byte[] decryptedprivate = encryptCipher.doFinal(loadedprivate);
				// recreate it
				PKCS8EncodedKeySpec ks2 =  new PKCS8EncodedKeySpec(decryptedprivate);
			    KeyFactory kf2 = KeyFactory.getInstance("RSA");
			    privateKey = kf2.generatePrivate(ks2);
			    
			    // can remove
			    /*
			    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");   
			    cipher.init(Cipher.ENCRYPT_MODE, publicKey); 
			    String teststring = "only a test";
			    byte[] testarray =  cipher.doFinal(teststring.getBytes());
			    
			    cipher.init(Cipher.DECRYPT_MODE, privateKey);  
				String testhope =  new String(cipher.doFinal(testarray));
			    System.out.println(testhope);
			    */
			    // *****************************************************
			    				
				//
				// all cached so create a UUID
				// MyInstanceID "########-####-####-####-############" is not used from config, there as placeholder
				MyInstanceID = UUID.randomUUID().toString();
				r2sconifg.put("MyInstanceID", MyInstanceID); // only here so System.out works below
				System.out.println("MyInstanceID" + MyInstanceID);
				// something was missing, so through error
				if (invalidconfig == 1 ) {
				    System.out.println(MyMicroserviceName + " Information missing in MSTAConfiguration.json in WEB-INF folder");
			    	throw(new NullPointerException (MyMicroserviceName + " Information missing in MSTAConfiguration.json in WEB-INF folder"));		
				}
		    	System.out.println(MyMicroserviceName + " WEB-INF");
			    System.out.println(r2sconifg.toString());
			}
			else {
				// ********************************************
				// TO DO
				// DO REGISTRATION WITH MST-Auth SErVER
		    	String jsonstr = "";
		    	
		    	JSONObject jsonobj =  new JSONObject(jsonstr);
			    
			    //
			    // save my info
			    //
				MSTA_CONNECTION_TIMEOUT = jsonobj.getInt("MSTA_CONNECTION_TIMEOUT");
				MSTA_RESPONSE_TIMEOUT = jsonobj.getInt("MSTA_RESPONSE_TIMEOUT");
				MSTA_TIMEOUT_WAIT = jsonobj.getInt("MSTA_TIMEOUT_WAIT");
				MSTA_TRIES = jsonobj.getInt("MSTA_TRIES");
			    MyMicroserviceName = jsonobj.getString("MyMicroserviceName");
			    MyMicroserviceID = jsonobj.getString("MyMicroserviceID");
			    MyInstanceID = jsonobj.getString("MyInstanceID");
			    MyURI = jsonobj.getString("MyURI");
			    
			    //
			    // create the graphname_to_auth hash table
			    //
			    JSONArray  jsonms = jsonobj.getJSONArray("MicroserviceGraph");
			    for (int i = 0; i < jsonms.length(); i++) { 
			    	 JSONObject GraphObject = jsonms.getJSONObject(i);  
			    	 String graphname = GraphObject.getString("GraphName");
			    	 graphname_to_auth.put(graphname, GraphObject);
			    }
		    	System.out.println(MyMicroserviceName+ " MST-Auth Server");
			    System.out.println(jsonobj.toString());
			}
		} 
		catch (IOException e) {
			System.out.println(e.toString());
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
	}

	// *******************************************************************
	//
	// the rest calls RECEIVE routines
	//
	// we save the methods (get, post etc.)
	// check the header (all things MST-Auth receiving)
	// pass to the client if all things are good with the check
	// TO DO ADD OPTIONAL ENCRYPTION ON ReSPONSE
	// *******************************************************************
	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		InboundMethod = "GET";
		String decryptedbody = CheckInboundHeader(request);
		
		myresponse = response;
		MST_Client.doGet(request, response, decryptedbody);
		
		InboundMethod = "";
		myresponse = null;
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		InboundMethod = "POST";
		String decryptedbody = CheckInboundHeader(request);
		
		myresponse = response;
		MST_Client.doPost(request, response, decryptedbody);
		InboundMethod = "";
		myresponse = null;
	}

	/**
	 * @see HttpServlet#doPut(HttpServletRequest, HttpServletResponse)
	 */
	protected void doPut(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		InboundMethod = "PUT";
		String decryptedbody = CheckInboundHeader(request);
		
		myresponse = response;
		MST_Client.doPut(request, response, decryptedbody);
		InboundMethod = "";
		myresponse = null;
	}

	/**
	 * @see HttpServlet#doDelete(HttpServletRequest, HttpServletResponse)
	 */
	protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		InboundMethod = "DELETE";
		String decryptedbody = CheckInboundHeader(request);
		
		myresponse = response;
		MST_Client.doDelete(request, response, decryptedbody);
		InboundMethod = "";
		myresponse = null;
	}

	// *******************************************************************
	//
	// shared SEND and RECEIVE methods
	//
	// *******************************************************************

	// *******************************************************************
	// 
	// all things authorization
	//
	// used by both SEND and RECEIVE
	// to check if this type of communication is authorized
	//
	// *******************************************************************
	private int CheckAuthorization(String direction, String type) {
	    System.out.println("Graph Name: " + GraphName);
		JSONObject GraphObject = graphname_to_auth.get(GraphName);
	    //System.out.println(GraphObject.toString());
	    JSONArray GraphAuth = GraphObject.getJSONArray("GraphAuthorizations");
	    int authorized = 0;
	    // loop through graph
	    for (int i = 0; i < GraphAuth.length(); i++) { 
	    	JSONObject graphauths = GraphAuth.getJSONObject(i); 
	    	if(graphauths.has(direction)) {
	    		JSONArray Auths = graphauths.getJSONArray(direction);
	    		// loop through authorizations
	    	    for (int y = 0; y < Auths.length(); y++) { 
	    	    	// auth must equal type 
	    	    	if (Auths.get(y).equals(type)) authorized = 1;
	    	    	// or equal * if RECEIVE
	    	    	else if (direction.equals("RECEIVE") && Auths.get(y).equals("*")) authorized = 1;	    	    		
	    	    }
	    	}
	    	
	    	// direction passed in is SEND or RECEIVE
	    	// so we have to check for special case of SEND that is FORWARD
	    	//
	    	// so if direction is SEND and has graph has an auth of FORWARD
	    	if(direction.equals("SEND") && graphauths.has("FORWARD")) {
	    		JSONArray Auths = graphauths.getJSONArray("FORWARD");
	    		// loop through authorizations
	    	    for (int z = 0; z < Auths.length(); z++) { 
	    	    	// check to see if the passed in method is the same as in inbound method 
	    	    	if (Auths.get(z).equals(type) && type.equals(InboundMethod)) authorized = 1;	
	    	    }
	    	} 
	    }
	    return authorized;
	}
	
	// *******************************************************************
	//
	// RECEIVE methods
	//
	// *******************************************************************
	
	// *******************************************************************
	//
	// check the header (all things MST-Auth receiving)
	//
	// *******************************************************************
	private String CheckInboundHeader(HttpServletRequest request) {
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
	    	throw(new IllegalArgumentException (MyMicroserviceName + ": Invalid Signature"));		
		}
	  	String newbody = jb.toString();
		
		// see if there is a MST-AUTH header
		String mstaheader = request.getHeader("MST-AUTH");
		if (mstaheader == null) {
			// no header, so from outside
			GraphName = MyMicroserviceName;
			// check to see if we can receive from outside
			if ((CheckAuthorization("RECEIVE", "*") == 0)) {
				System.out.println("Throw1");
		    	throw(new IllegalArgumentException (MyMicroserviceName + ": Non MST-AUTH rest calls not avalable"));		
			}
		}	
		else {
			// there is a header
			// first things first, signature is required
			String graphensignature = request.getHeader("MST-AUTH-Signature");
			if (graphensignature == null) throw(new IllegalArgumentException (MyMicroserviceName + ": Non MST-AUTH rest calls not avalable"));
		    byte[] signature = Base64.getDecoder().decode(graphensignature);
		
		    try {
			    MessageDigest messageDigest;
			    messageDigest = MessageDigest.getInstance("SHA-256");
			    messageDigest.update(mstaheader.getBytes());
			    String stringHash = new String(messageDigest.digest());
			  
			    Signature sign;
			    sign = Signature.getInstance("SHA256withRSA");
				sign.initVerify((PublicKey) publicKey);
				sign.update(stringHash.getBytes(), 0, stringHash.getBytes().length );
				boolean verify = sign.verify(signature);
				System.out.println("Signature " +  (verify ? "OK" : "Not OK"));	
				if (verify == false) throw(new IllegalArgumentException (MyMicroserviceName + ": Invalid Signature"));	
				
				// good signature
				// ok lets check encryption			
				String graphencryption = request.getHeader("MST-AUTH-Encryption");
				if (graphencryption == null) throw(new IllegalArgumentException (MyMicroserviceName + ": Non MST-AUTH rest calls not avalable"));

				//  get the encryption type from the header
		    	JSONObject jsonenc =  new JSONObject(graphencryption);
				byte[] jsonsecret = jsonenc.getString("Secret").getBytes();			    
			    byte[] decodedsecret = (Base64.getDecoder().decode(jsonsecret));
			    
			    String graphencryptiontype = jsonenc.getString("Encryption");	    
				if (!graphencryptiontype.equals("NONE")) {
					// something to decrypt
					// decrypt the temp secret
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
				// TODO Auto-generated catch block
				e.printStackTrace();
		    	throw(new IllegalArgumentException (MyMicroserviceName + ": Invalid Signature"));		
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
		    	throw(new IllegalArgumentException (MyMicroserviceName + ": Invalid Signature"));		
			} catch (SignatureException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
		    	throw(new IllegalArgumentException (MyMicroserviceName + ": Invalid Signature"));		
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
		    	throw(new IllegalArgumentException (MyMicroserviceName + ": Invalid Signature"));		
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
		    	throw(new IllegalArgumentException (MyMicroserviceName + ": Invalid Signature"));		
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
		    	throw(new IllegalArgumentException (MyMicroserviceName + ": Invalid Signature"));		
			}
			
			// good header (fully decrypted if encrypted)
			// can I receive from them?
			JSONObject jsonheader = new JSONObject(mstaheader);	
			GraphName = jsonheader.getString("MicroserviceName");
			if ((CheckAuthorization("RECEIVE", InboundMethod) == 0)) {
				System.out.println("Throw2");
		    	throw(new IllegalArgumentException (MyMicroserviceName + ": Non MST-AUTH rest calls not avalable"));
			}
			
			// anything else we want to do with the jsonheader put it here
			// OY
		}
		return newbody;
	}

	// *******************************************************************
	//
	// SEND methods
	//
	// *******************************************************************
	
	// *******************************************************************
	//
	// build the headers (all things MST-Auth sending)
	//
	// *******************************************************************
	private void BuildHeaders() {
		// create header
		JSONObject newobj = new JSONObject();		
		newobj.put("MicroserviceName", MyMicroserviceName);
		newobj.put("MicroserviceID", MyMicroserviceID);
		newobj.put("InstanceID", MyInstanceID);
	    Date date = new Date();
	    String timestamp = new Timestamp(date.getTime()).toString();	// use java.sql
		newobj.put("timestamp", timestamp);
		
		String newheader = newobj.toString();
		String graphencryption;
	    String sendSecret = "";
		try {
		
			PublicKey graphkey = graphname_to_public.get(GraphName);
		    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");   
		    cipher.init(Cipher.ENCRYPT_MODE, graphkey); 
		    
			JSONObject GraphObject = graphname_to_auth.get(GraphName);

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
		    	throw(new IllegalArgumentException (MyMicroserviceName + ": Build Header Invalid Arguments"));		
		    }
		} catch (NoSuchAlgorithmException e) {
		 //TODO Auto-generated catch block
			e.printStackTrace();
	    	throw(new IllegalArgumentException (MyMicroserviceName + ": Build Header Invalid Arguments"));		
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
	    	throw(new IllegalArgumentException (MyMicroserviceName + ": Build Header Invalid Arguments"));		
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
	    	throw(new IllegalArgumentException (MyMicroserviceName + ": Build Header Invalid Arguments"));		
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
	    	throw(new IllegalArgumentException (MyMicroserviceName + ": Build Header Invalid Arguments"));		
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
	    	throw(new IllegalArgumentException (MyMicroserviceName + ": Build Header Invalid Arguments"));		
		}
		
		// send the body
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
	
			Signature sign = Signature.getInstance("SHA256withRSA");
			sign.initSign((java.security.PrivateKey) privateKey);
			sign.update(stringHash.getBytes(), 0,stringHash.length() );
			byte[] signature = sign.sign();
			String s = Base64.getEncoder().encodeToString(signature);			  
		    mstauthbuilder.header("MST-AUTH-Signature", s);
		    
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
	    	throw(new IllegalArgumentException (MyMicroserviceName + ": Build Header Invalid Arguments"));		
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
	    	throw(new IllegalArgumentException (MyMicroserviceName + ": Build Header Invalid Arguments"));		
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
	    	throw(new IllegalArgumentException (MyMicroserviceName + ": Build Header Invalid Arguments"));		
		}

	    //System.out.println(MyMicroserviceName + ": Setting Header");
		
	}

	
	// *******************************************************************
	//
	// routines that let the client create the SEND message
	// 		for now we have only implemented SetMethodWithBodyString String type
	//
	// *******************************************************************
	public void SetMicroservice(String microservicename) {
		OutboundBody = "";
		GraphName = microservicename;
		JSONObject GraphObject = graphname_to_auth.get(GraphName);
		GraphUID = GraphObject.getString("GraphURI");
		try {
			mstauthbuilder = HttpRequest.newBuilder()
				.uri(new URI(GraphUID))
				.timeout(Duration.ofMillis(MSTA_RESPONSE_TIMEOUT));
		} 
		catch (URISyntaxException e) {
			e.printStackTrace();
		}
	}
	
	public void SetMethodWithBodyString(String method, String body ) {	
		// make sure this method is authorized
		if ((CheckAuthorization("SEND", method) == 0)) {
	    	throw(new IllegalArgumentException (MyMicroserviceName + ": " + method + " not avalable"));		
		}
		OutboundMethod = method;
		OutboundBody = body;
	}

	// add a header
	public void SetHeader(String name, String value ) {	
		mstauthbuilder.header(name, value);	// example mstauthbuilder.header("Content-Type", "application/json; utf-8");
		
	}
	// *******************************************************************
	//
	// the actual send
	//
	// *******************************************************************
	public HttpResponse SendRequest() {	
		
		  BuildHeaders();
		  
		  // build the request that the client has been working on
		  HttpRequest mstrequest = mstauthbuilder.build();
		  
		  // config the client
		  HttpClient mstclient = HttpClient.newBuilder()
			      .connectTimeout(Duration.ofMillis(MSTA_CONNECTION_TIMEOUT))	// time out to connect
			      .build();

		  // get ready for send
		  int mytries = MSTA_TRIES;
		  int retcode = 200;
		  String errorstring;
		  errorstring = "";
		  try 
		  {
			  // do the acutal send
			  
			  //System.out.println("CLIENT SENDING");			  
			  HttpResponse<String> mstresponse = mstclient.send(mstrequest, BodyHandlers.ofString());
			  //System.out.println("CLIENT SENT");
			  retcode = mstresponse.statusCode();
			  if (retcode != 200 ) {
				  errorstring = ( "Response: " + mstresponse.body() + "; retcode: " + retcode);
				  System.out.println(errorstring );
				  mytries--;
				  if (mytries > 0) {
					  try 
					  {
						  TimeUnit.MILLISECONDS.sleep(MSTA_TIMEOUT_WAIT);	// add a little wait, to see if root will end
					  }
					  catch (JSONException | InterruptedException ie) 
					  {
						  throw new IOException("InterruptedException " + ie.toString());
					  }						  
				  }
			  }
			  else {
				  // 200 so good
				  return mstresponse;
			  } 
		  }
		  catch (java.net.http.HttpTimeoutException e) {
			  errorstring = ("Connection Timeout: " + e.toString() + ";");
			  System.out.println(errorstring);
			  //throw new IOException("R2Lib Timeout: " + e.toString());	// catch TIMEOUT here
			  mytries--;
			  if (mytries > 0) {
				  try 
				  {
					  TimeUnit.MILLISECONDS.sleep(MSTA_TIMEOUT_WAIT);	// add a little wait, to see if root will end
				  }
				  catch (JSONException | InterruptedException ie) 
				  {
					  errorstring = errorstring + "InterruptedException" + ie.toString() + ";";
					  return null;
				  }
			  }
		  }
		  catch (Exception e) 
		  { 
			  errorstring = (errorstring + "Exception: " + e.toString() + ";");
			  System.out.println("MST-Auth Send Exception: " + e.toString());
			  mytries--;
			  if (mytries > 0) {
				  try 
				  {
					  TimeUnit.MILLISECONDS.sleep(MSTA_TIMEOUT_WAIT);	// add a little wait, to see if root will end
				  }
				  catch (JSONException | InterruptedException ie) 
				  {
					  errorstring = errorstring + "InterruptedException" + ie.toString() + ";";
					  return null;
				  }
			  }
		  }
		  return null;
	}

}
