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

public class MST_Auth_ServerServlet extends MST_Auth_Servlet {
	private static final  int CASSANDRA = 1;	// set to 0 to disable cassandra
	public static Cluster CASSANDRA_CLUSTER = null;
	private Session CASSANDRA_SESSION = null;
    private static String CASSANDRA_URL = "127.0.0.1";
	private static Integer CASSANDRA_PORT = 9042;
	//private static String CASSANDRA_AUTH = "";
	//private static String CASSANDRA_USER = ""; 
	//private static String CASSANDRA_PASSWORD = ""; 
	

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
		CassandraCreate();
		//String input = "{\"sending_servicename\":\"MSTABusiness\",\"sending_serviceid\":\"237367ff-ed9b-4d9c-b636-ad0d28ac5f62\",\"create_timestamp\":\"2022-11-02 18:32:25.71\",\"sending_instanceid\":\"fe8a5797-1cd2-4083-82b6-3d3ba9e40a49\",\"root_msgid\":\"a42d8262-0d55-49f9-aef6-5ffc8bcd35df\",\"receiving_serviceid\":\"0534fe29-3dc4-4641-bc94-a939d0d8ba71\",\"msgid\":\"3f25c69a-1794-401f-a684-02532ba7439f\",\"receiving_servicename\":\"MSTADataProvider\",\"parent_msgid\":\"6628f71d-eb88-4d8e-9528-8f7b3350538a\"}";
		//String jsonquery = "INSERT INTO mstauth.service_tree JSON '" + input +"'";
		//CassandraInsert(jsonquery);

	}

	public void destroy() {
		super.destroy();
		if ( CASSANDRA == 1 ) {
			CASSANDRA_CLUSTER.close();	// not sure this does anything	
		}
	}
	
	public void CassandraInsert(String statement) {
		if ( CASSANDRA == 1 ) {
			Statement  st = new SimpleStatement(statement);
			if (CASSANDRA_CLUSTER == null || CASSANDRA_CLUSTER.isClosed()) CassandraCreate();		
			CASSANDRA_SESSION.execute(st);
		}
		
	}

	private void CassandraCreate() {
		if ( CASSANDRA == 1 ) {
			
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
	
	public void CassandraLog(String input) {
		//System.out.println("OY2 " + input);
		String jsonquery = "INSERT INTO mstauth.service_tree JSON '" + input +"'";
		CassandraInsert(jsonquery);
	}
	
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

		MST_Auth_ServerClientWrapper wrapper = new MST_Auth_ServerClientWrapper(MSTAUtils, MSTA_CONNECTION_TIMEOUT, MSTA_RESPONSE_TIMEOUT, MSTA_TIMEOUT_WAIT, MSTA_TRIES, this);
		try {
			wrapper.doGet(request, response);
		} catch (IOException e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}
	}


	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

		MST_Auth_ServerClientWrapper wrapper = new MST_Auth_ServerClientWrapper(MSTAUtils, MSTA_CONNECTION_TIMEOUT, MSTA_RESPONSE_TIMEOUT, MSTA_TIMEOUT_WAIT, MSTA_TRIES, this);
		try {
			wrapper.doPost(request, response);
		} catch (IOException e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}			
	}


	protected void doPut(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		MST_Auth_ServerClientWrapper wrapper = new MST_Auth_ServerClientWrapper(MSTAUtils, MSTA_CONNECTION_TIMEOUT, MSTA_RESPONSE_TIMEOUT, MSTA_TIMEOUT_WAIT, MSTA_TRIES, this);
		try {
			wrapper.doPut(request, response);
		} catch (IOException e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}			
	}


	protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		MST_Auth_ServerClientWrapper wrapper = new MST_Auth_ServerClientWrapper(MSTAUtils, MSTA_CONNECTION_TIMEOUT, MSTA_RESPONSE_TIMEOUT, MSTA_TIMEOUT_WAIT, MSTA_TRIES, this);
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
