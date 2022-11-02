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
public class MST_Auth_Servlet extends MST_Auth_BaseServlet {
	//private HttpRequest.Builder mstauthbuilder;
	////////////////////////////////////////////////
	// temp cassandra stuff
	private static final  int CASSANDRA = 0;	// set to 0 to disable cassandra
	public static Cluster CASSANDRA_CLUSTER = null;
	private Session CASSANDRA_SESSION = null;
    private static String CASSANDRA_URL = "127.0.0.1";
	private static Integer CASSANDRA_PORT = 9042;
	//private static String CASSANDRA_AUTH = "";
	//private static String CASSANDRA_USER = ""; 
	//private static String CASSANDRA_PASSWORD = ""; 
	private int RESTOREPROPERTYDEFAULTS = 0;
	
	// parameters either from properties, MSTAConfiguration.json or from MST-Auth Register
	
	//
	//the in memory hash map of all things MST-AUTH
	//private LinkedHashMap<String, JSONObject> graphname_to_auth = null;
	//private LinkedHashMap<String, PublicKey> graphname_to_public = null;

	private MST_Auth_Client MST_Client;       
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

		super.init(config);
		MST_Client = new MST_Auth_Client();
		
		//
		// initialize some variables
		//
		MSTAUtils.MyMicroserviceName = "";
		MSTAUtils.MyMicroserviceID = "";
		MSTAUtils.MyInstanceID = "";
		//MSTAUtils.secretKey = null;
		
		MSTAUtils.graphname_to_auth = new LinkedHashMap<String, JSONObject>();
		MSTAUtils.graphname_to_public = new LinkedHashMap<String, PublicKey>();
		
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
			    	throw(new ServletException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": Restore Property Defaults did NOT work"));	
		    	 }
	    	 }

	    } catch (IOException  e) {
		    System.out.println("property not found load from default");		    	
			// get the json string from the WEB-INF directory			
			InputStream stream = classLoader.getResourceAsStream("../MSTAConfiguration.json");
		    //System.out.println(stream);
			if (stream == null) {
			    System.out.println("MSTAConfiguration.json missing from WEB-INF folder");
		    	throw(new NullPointerException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": MSTAConfiguration.json missing from WEB-INF folder"));		
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
		    	throw(new NullPointerException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": MSTAConfiguration.json missing from WEB-INF folder"));		
			}
	    }

		// we now have config in strproperties
		try {
			//
		    //System.out.println(strproperties);
			JSONObject r2sconifg =  new JSONObject(strproperties);
			
			// MSTA_URL is required if MSTA_DO_INIT is not 0
			int URL_REQUIRED = 1;
			if(r2sconifg.has("MSTA_DO_INIT")) {
				MSTAUtils.MSTA_DO_INIT = r2sconifg.getInt("MSTA_DO_INIT");
				if (MSTAUtils.MSTA_DO_INIT == 0) 
					URL_REQUIRED = 0;
			}
			if(r2sconifg.has("MSTA_URL"))
				MSTAUtils.MSTA_URL = r2sconifg.getString("MSTA_URL");
			else {
				if (URL_REQUIRED == 1) {
				    System.out.println(MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": MSTA_URL missing MSTAConfiguration.json in WEB-INF folder");
			    	throw(new NullPointerException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": MSTA_URL missing MSTAConfiguration.json in WEB-INF folder"));		
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
					MSTAUtils.MyMicroserviceName = r2sconifg.getString("MyMicroserviceName");
				//System.out.println(MyMicroserviceName);
				if(!r2sconifg.has("MyMicroserviceID")) invalidconfig = 1; else
					MSTAUtils.MyMicroserviceID = r2sconifg.getString("MyMicroserviceID");
				if(!r2sconifg.has("MyURI")) invalidconfig = 1; else
					MSTAUtils.MyURI = r2sconifg.getString("MyURI");
				if(!r2sconifg.has("MyPublic")) invalidconfig = 1; else
				{
			    	String graphpublic = r2sconifg.getString("MyPublic");
			    	MSTAUtils.decodepublic = Base64.getDecoder().decode(graphpublic);		    
					//MSTAUtils.MyPublic = r2sconifg.getString("MyPublic");
				}
				if(!r2sconifg.has("MicroserviceGraph")) invalidconfig = 1; else {
				    JSONArray jsonms = r2sconifg.getJSONArray("MicroserviceGraph");
				    KeyFactory kfinit = KeyFactory.getInstance("RSA");
				    for (int i = 0; i < jsonms.length(); i++) { 
				    	 JSONObject GraphObject = jsonms.getJSONObject(i);  
				    	 String graphname = GraphObject.getString("GraphName");
				    	 MSTAUtils.graphname_to_auth.put(graphname, GraphObject);

				    	String graphpublic = GraphObject.getString("GraphPublic");
					    byte[] decodepublic = Base64.getDecoder().decode(graphpublic);		    
					    X509EncodedKeySpec ks3 =  new X509EncodedKeySpec(decodepublic);
					    PublicKey graphKey = kfinit.generatePublic(ks3);
					    MSTAUtils.graphname_to_public.put(graphname, graphKey);			    
				    }
				}
				
				// *****************************************************
			    // REMOVE WHEN WE HAVE MST-Auth and Register
				//
				SecretKey secretKey = null;
				if(!r2sconifg.has("MyHash")) invalidconfig = 1; else
				{
					String MyHash = r2sconifg.getString("MyHash");
					byte[] decodesecret = Base64.getDecoder().decode(MyHash);		    
				    secretKey = new SecretKeySpec(decodesecret, 0, decodesecret.length, "AES"); 
				}
				
			    //byte[] decodepublic = Base64.getDecoder().decode(MSTAUtils.MyPublic);		    
							
			    InputStream stream2 = classLoader.getResourceAsStream("../privateKey.key");
			    //System.out.println(stream2);
				if (stream2 == null) {
				    System.out.println("privateKey missing from WEB-INF folder");
			    	throw(new NullPointerException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": MSTAConfiguration.json missing from WEB-INF folder"));		
				}
				ObjectInputStream oin2 = new ObjectInputStream(stream2);
			    byte[] loadedprivate = (byte[]) oin2.readObject();
			    oin2.close();
			    stream2.close();

				// decrypt it
			    Cipher encryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			    encryptCipher.init(Cipher.DECRYPT_MODE, secretKey);
			    MSTAUtils.decryptedprivate = encryptCipher.doFinal(loadedprivate);
			    			    			    				
				//
				// all cached so create a UUID
				// MyInstanceID "########-####-####-####-############" is not used from config, there as placeholder
			    MSTAUtils.MyInstanceID = UUID.randomUUID().toString();
				r2sconifg.put("MyInstanceID", MSTAUtils.MyInstanceID); // only here so System.out works below
				//System.out.println("MyInstanceID" + MyInstanceID);
				// something was missing, so through error
				if (invalidconfig == 1 ) {
				    System.out.println(MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": Information missing in MSTAConfiguration.json in WEB-INF folder");
			    	throw(new NullPointerException (MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": Information missing in MSTAConfiguration.json in WEB-INF folder"));		
				}
		    	System.out.println(MSTAUtils.MyMicroserviceName + ":" + MSTAUtils.MyMicroserviceID + ":" + MSTAUtils.MyInstanceID + ": WEB-INF");
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
				
				MSTAUtils.MyMicroserviceName = jsonobj.getString("MyMicroserviceName");
				MSTAUtils.MyMicroserviceID = jsonobj.getString("MyMicroserviceID");
				MSTAUtils.MyInstanceID = jsonobj.getString("MyInstanceID");
				MSTAUtils.MyURI = jsonobj.getString("MyURI");
			    
			    //
			    // create the graphname_to_auth hash table
			    //
			    JSONArray  jsonms = jsonobj.getJSONArray("MicroserviceGraph");
			    for (int i = 0; i < jsonms.length(); i++) { 
			    	 JSONObject GraphObject = jsonms.getJSONObject(i);  
			    	 String graphname = GraphObject.getString("GraphName");
			    	 MSTAUtils.graphname_to_auth.put(graphname, GraphObject);
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
		if ( CASSANDRA == 1 ) {
			CASSANDRA_CLUSTER.close();	// not sure this does anything	
		}
	}
	
	public void CassandraInsert(String statement) {
		if ( CASSANDRA == 1 ) {
			Statement  st = new SimpleStatement(statement);
			 //st.setConsistencyLevel(ConsistencyLevel.LOCAL_QUORUM);
			//System.out.println(st);			
			if (CASSANDRA_CLUSTER == null || CASSANDRA_CLUSTER.isClosed()) CassandraCreate();		
			CASSANDRA_SESSION.execute(st);
		}
		
	}

	private void CassandraCreate() {
		if ( CASSANDRA == 1 ) {
			
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
							  //throw new MSTAException(MyMicroserviceName + ":" + MyMicroserviceID + ":" + MyInstanceID + ": MST-Auth Cassandra InterruptedException " + ie.toString());
						  }						  
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
	

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

		MST_Auth_ClientWrapper wrapper = new MST_Auth_ClientWrapper(MSTAUtils, MSTA_CONNECTION_TIMEOUT, MSTA_RESPONSE_TIMEOUT, MSTA_TIMEOUT_WAIT, MSTA_TRIES, this);
		try {
			wrapper.doGet(request, response);
		} catch (IOException e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}
	}


	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

		MST_Auth_ClientWrapper wrapper = new MST_Auth_ClientWrapper(MSTAUtils, MSTA_CONNECTION_TIMEOUT, MSTA_RESPONSE_TIMEOUT, MSTA_TIMEOUT_WAIT, MSTA_TRIES, this);
		try {
			wrapper.doPost(request, response);
		} catch (IOException e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}			
	}


	protected void doPut(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		MST_Auth_ClientWrapper wrapper = new MST_Auth_ClientWrapper(MSTAUtils, MSTA_CONNECTION_TIMEOUT, MSTA_RESPONSE_TIMEOUT, MSTA_TIMEOUT_WAIT, MSTA_TRIES, this);
		try {
			wrapper.doPut(request, response);
		} catch (IOException e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}			
	}


	protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		MST_Auth_ClientWrapper wrapper = new MST_Auth_ClientWrapper(MSTAUtils, MSTA_CONNECTION_TIMEOUT, MSTA_RESPONSE_TIMEOUT, MSTA_TIMEOUT_WAIT, MSTA_TRIES, this);
		try {
			wrapper.doDelete(request, response);
		} catch (IOException e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}
	}
	
}
