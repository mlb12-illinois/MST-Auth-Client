package mst_auth_library;

import mst_auth_client.MST_Auth_Client;
//import software.aws.mcs.auth.SigV4AuthProvider;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
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
import java.util.LinkedHashMap;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.datastax.driver.core.Cluster;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import com.datastax.driver.core.Session;
import com.datastax.driver.core.SimpleStatement;
import com.datastax.driver.core.Statement;


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
	private int CASSANDRA = 0;
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
	private JSONObject jsonheader;
	private String InboundMethod;
	private String OutboundMethod;
	private String OutboundBody;
	private String OutboundService;	
	
	private String sending_servicename;	
	private UUID sending_instanceid;
	private UUID sending_serviceid;
	private String receiving_servicename;	
	private UUID receiving_instanceid;
	private UUID receiving_serviceid;

	private int NewMessageChain;
	private UUID root_msgid;
	private UUID parent_msgid;
	private UUID msgid;
	
	private Timestamp create_timestamp;
	
	private MST_Auth_Client MST_Client;
	private HttpRequest.Builder mstauthbuilder;
	private HttpServletResponse myresponse;
	public JSONObject inputjson;
	
	private static final long serialVersionUID = 1L;
	
	////////////////////////////////////////////////
	// temp cassandra stuff
	public static Cluster CASSANDRA_CLUSTER;
	private Session CASSANDRA_SESSION;
    private static String CASSANDRA_URL = "127.0.0.1";
	private static Integer CASSANDRA_PORT = 9042;
	private static String CASSANDRA_AUTH = "";
	private static String CASSANDRA_USER = ""; 
	private static String CASSANDRA_PASSWORD = ""; 
       
     public MST_Auth_Servlet() {
        super();
    }

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
		MyMicroserviceName = "";
		MyMicroserviceID = "";
		MyInstanceID = "";
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
			    	throw(new ServletException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": Restore Property Defaults did NOT work"));	
		    	 }
	    	 }

	    } catch (IOException  e) {
		    System.out.println("property not found load from default");		    	
			// get the json string from the WEB-INF directory			
			InputStream stream = classLoader.getResourceAsStream("../MSTAConfiguration.json");
		    //System.out.println(stream);
			if (stream == null) {
			    System.out.println("MSTAConfiguration.json missing from WEB-INF folder");
		    	throw(new NullPointerException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": MSTAConfiguration.json missing from WEB-INF folder"));		
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
		    	throw(new NullPointerException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": MSTAConfiguration.json missing from WEB-INF folder"));		
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
				    System.out.println(MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": MSTA_URL missing MSTAConfiguration.json in WEB-INF folder");
			    	throw(new NullPointerException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": MSTA_URL missing MSTAConfiguration.json in WEB-INF folder"));		
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
				//System.out.println(MyMicroserviceName);
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
				
			    byte[] decodepublic = Base64.getDecoder().decode(MyPublic);		    
			    X509EncodedKeySpec ks3 =  new X509EncodedKeySpec(decodepublic);
			    KeyFactory kf3 = KeyFactory.getInstance("RSA");
			    publicKey = kf3.generatePublic(ks3);
				
				
			    InputStream stream2 = classLoader.getResourceAsStream("../privateKey.key");
			    //System.out.println(stream2);
				if (stream2 == null) {
				    System.out.println("privateKey missing from WEB-INF folder");
			    	throw(new NullPointerException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": MSTAConfiguration.json missing from WEB-INF folder"));		
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
			    			    				
				//
				// all cached so create a UUID
				// MyInstanceID "########-####-####-####-############" is not used from config, there as placeholder
				MyInstanceID = UUID.randomUUID().toString();
				r2sconifg.put("MyInstanceID", MyInstanceID); // only here so System.out works below
				//System.out.println("MyInstanceID" + MyInstanceID);
				// something was missing, so through error
				if (invalidconfig == 1 ) {
				    System.out.println(MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": Information missing in MSTAConfiguration.json in WEB-INF folder");
			    	throw(new NullPointerException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": Information missing in MSTAConfiguration.json in WEB-INF folder"));		
				}
		    	System.out.println(MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": WEB-INF");
			    //System.out.println(r2sconifg.toString());
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
		    	//System.out.println(MyMicroserviceName+ " MST-Auth Server");
			    //System.out.println(jsonobj.toString());
			}
		} 
		catch (IOException e) {
			System.out.println(e.toString());
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}	
		
		/////////////////////////////////////////
		// temp cassandra stuff
		CassandraCreate();
	}

	public void destroy() {
		CASSANDRA_CLUSTER.close();	// not sure this does anything		
	}

	private void CassandraCreate() throws ServletException {
		if ( CASSANDRA == 0 ) return;
		/////////////////////////////////////////
		// temp cassandra stuff
		int tries = 3;
		while (tries > 0)
		{
			try {
				CASSANDRA_CLUSTER = Cluster.builder()
						.addContactPoint(CASSANDRA_URL)
						.withPort(CASSANDRA_PORT)
//						.withAuthProvider(new SigV4AuthProvider(CASSANDRA_AUTH))
//		                .withSSL()
//						.withCredentials(CASSANDRA_USER, CASSANDRA_PASSWORD)
						.build();

				CASSANDRA_SESSION = CASSANDRA_CLUSTER.connect();
				CASSANDRA_SESSION.execute("USE mstauth");
				return;
			}
			catch(Exception e) {
				tries --;
				  System.out.println("MST-Auth" + e.toString());
				  if (tries > 0) {
					  try 
					  {
						  TimeUnit.MILLISECONDS.sleep(5000);	// add a little wait, to see if root will end
					  }
					  catch (JSONException | InterruptedException ie) 
					  {
						  throw new ServletException(MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": MST-Auth Cassandra InterruptedException " + ie.toString());
					  }						  
				  }
			}
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
	private void HandleException(String e) {
		// to do add communication to server
	    System.out.println(e);		
	}
	

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		try {
			InboundMethod = "GET";
			String decryptedbody = CheckInboundHeader(request);
			
			myresponse = response;
			MST_Client.doGet(request, response, decryptedbody);
			
			InboundMethod = "";
			myresponse = null;
		}
		catch (MSTAException e) {
			HandleException(e.toString());
		}
	}


	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		try {
			InboundMethod = "POST";
			String decryptedbody = CheckInboundHeader(request);
			
			myresponse = response;
			MST_Client.doPost(request, response, decryptedbody);
			InboundMethod = "";
			myresponse = null;
		}
		catch (MSTAException e) {
			HandleException(e.toString());			
		}
	}


	protected void doPut(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		try {
			InboundMethod = "PUT";
			String decryptedbody = CheckInboundHeader(request);
			
			myresponse = response;
			MST_Client.doPut(request, response, decryptedbody);
			InboundMethod = "";
			myresponse = null;
		}
		catch (MSTAException e) {
			HandleException(e.toString());			
		}
	}


	protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		try {
			InboundMethod = "DELETE";
			String decryptedbody = CheckInboundHeader(request);
			
			myresponse = response;
			MST_Client.doDelete(request, response, decryptedbody);
			InboundMethod = "";
			myresponse = null;
		}
		catch (MSTAException e) {
			HandleException(e.toString());			
		}
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
	private int CheckAuthorization(String service, String direction, String type) {
	    //System.out.println("My name: " + MyMicroserviceName + " Graph Name: " + service + " type: " + type);
		JSONObject GraphObject = graphname_to_auth.get(service);
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
	private String CheckInboundHeader(HttpServletRequest request) throws MSTAException, ServletException {
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
	    	throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": Invalid Signature"));		
		}
	  	String newbody = jb.toString();
		
		// see if there is a MST-AUTH header
		String mstaheader = request.getHeader("MST-AUTH");
		if (mstaheader == null) {
			// no header, so from outside
			// set a flag for others
			NewMessageChain = 1;
			// check to see if we can receive from outside
			if ((CheckAuthorization(MyMicroserviceName, "RECEIVE", "*") == 0)) {
				System.out.println("Throw1");
		    	throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": Non MST-AUTH rest calls not avalable"));		
			}
		}	
		else {
			// there is a header
			// first things first, signature is required
			String graphensignature = request.getHeader("MST-AUTH-Signature");
			if (graphensignature == null) 
	    		throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": Non MST-AUTH rest calls not avalable"));		
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
				//System.out.println("Signature " +  (verify ? "OK" : "Not OK"));	
				if (verify == false) throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": Invalid Signature"));	
				
				// good signature
				// ok lets check encryption			
				String graphencryption = request.getHeader("MST-AUTH-Encryption");
				if (graphencryption == null) throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": Non MST-AUTH rest calls not avalable"));

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
				e.printStackTrace();
		    	throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": InvalidKeyException" + e));		
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
		    	throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": NoSuchAlgorithmException" + e));		
			} catch (SignatureException e) {
				e.printStackTrace();
		    	throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": SignatureException" + e));		
			} catch (NoSuchPaddingException e) {
				e.printStackTrace();
		    	throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": NoSuchPaddingException" + e));		
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
		    	throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": IllegalBlockSizeException" + e));		
			} catch (BadPaddingException e) {
				e.printStackTrace();
		    	throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": BadPaddingException" + e));		
			}
			
		    
			// good header (fully decrypted if encrypted)
			// can I receive from them?
			jsonheader = new JSONObject(mstaheader);	
			
			
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

		    if (!MyMicroserviceID.equals(receiving_serviceid.toString()))
		    	throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": " + receiving_serviceid + " wrong service id sent"));
		    if (!MyMicroserviceName.equals(receiving_servicename)) 
		    	throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": " + receiving_servicename + " wrong service name sent"));

			// track receipt
		    Date date = new Date();
		    String timestamp = new Timestamp(date.getTime()).toString();	// use java.sql
		    jsonheader.put("create_timestamp", timestamp);
		    //jsonheader.put("receiving_serviceid", MyMicroserviceID);
		    jsonheader.put("receiving_instanceid", MyInstanceID);
		    //jsonheader.put("receiving_servicename", MyMicroserviceName);
		    
		    if (CASSANDRA == 1) {
				String jsonquery = "INSERT INTO mstauth.service_tree JSON '" + jsonheader.toString() +"'";
				Statement  st = new SimpleStatement(jsonquery);
				  //st.setConsistencyLevel(ConsistencyLevel.LOCAL_QUORUM);
				//System.out.println(st);
				
				if (CASSANDRA_CLUSTER == null || CASSANDRA_CLUSTER.isClosed()) CassandraCreate();		
				CASSANDRA_SESSION.execute(st);
				
				// not a new chain so check auth
				if (NewMessageChain == 0 ) {
				    //System.out.println("Receive Header my name : " + MyMicroserviceName + " sender name: " + sending_servicename);
					if ((CheckAuthorization(sending_servicename, "RECEIVE", InboundMethod) == 0)) {
				    	throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": Non MST-AUTH rest calls not avalable"));
					}
				}
		    	
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
	private void BuildHeaders() throws ServletException, MSTAException {
		// create header
		JSONObject newobj = new JSONObject();		
		newobj.put("sending_servicename", MyMicroserviceName);		
		newobj.put("sending_serviceid", MyMicroserviceID);
		newobj.put("sending_instanceid", MyInstanceID);
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
		
	    if (CASSANDRA == 1) {		
			String jsonquery = "INSERT INTO mstauth.service_tree JSON '" + newobj.toString() +"'";
			Statement  st = new SimpleStatement(jsonquery);
			  //st.setConsistencyLevel(ConsistencyLevel.LOCAL_QUORUM);
			//System.out.println(st);
			
			if (CASSANDRA_CLUSTER == null || CASSANDRA_CLUSTER.isClosed()) CassandraCreate();		
			CASSANDRA_SESSION.execute(st);
	    }


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
		    	throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": Build Header Invalid Arguments"));		
		    }
		} catch (NoSuchAlgorithmException e) {
	    	throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": NoSuchAlgorithmException" + e));		
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
	    	throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": NoSuchPaddingException" + e));		
		} catch (InvalidKeyException e) {
			e.printStackTrace();
	    	throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": InvalidKeyException" + e));		
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
	    	throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": IllegalBlockSizeException" + e));		
		} catch (BadPaddingException e) {
			e.printStackTrace();
	    	throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": BadPaddingException" + e));		
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
			e.printStackTrace();
	    	throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": NoSuchAlgorithmException" + e));		
		} catch (InvalidKeyException e) {
			e.printStackTrace();
	    	throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": InvalidKeyException" + e));		
		} catch (SignatureException e) {
			e.printStackTrace();
	    	throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": SignatureException" + e));		
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
		OutboundService = microservicename;
		JSONObject GraphObject = graphname_to_auth.get(OutboundService);
		GraphUID = GraphObject.getString("GraphURI");
	    //System.out.println(MyMicroserviceName + OutboundService + " "+ GraphUID);
		
		try {
			mstauthbuilder = HttpRequest.newBuilder()
				.uri(new URI(GraphUID))
				.timeout(Duration.ofMillis(MSTA_RESPONSE_TIMEOUT));
		} 
		catch (URISyntaxException e) {
			e.printStackTrace();
		}
	}
	
	public void SetMethodWithBodyString(String method, String body ) throws MSTAException {	
		// make sure this method is authorized
	    //System.out.println("SetMethodWithBodyString : " + MyMicroserviceName);
		if ((CheckAuthorization(OutboundService, "SEND", method) == 0)) {
	    	throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": Invalid Send Authorization"));		
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
	public HttpResponse SendRequest() throws ServletException, MSTAException {	
		
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
				    	throw(new MSTAException (MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": InterruptedException" + ie));		
					  }						  
				  }
				  return mstresponse;
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
