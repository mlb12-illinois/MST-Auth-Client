package mst_auth_library;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.LinkedHashMap;
import java.util.concurrent.Semaphore;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONArray;
import org.json.JSONObject;

//*******************************************************************
//*******************************************************************
//*******************************************************************
//
// This is the main buffer for shared data
//
// It is created in MST_Auth_BaseServlet
// But it is poplulated in MST_Auth_Servlet
// 		which is all things data from MST-Auth Server
//
// Most of the data is fixed (strings and buffers(
// however there is a listsemaphore that MUST be used if accessing
//		any of the non static stuff (LinkedHashMap for now)
//
//*******************************************************************
//*******************************************************************
//*******************************************************************

public class MST_Auth_Utils {
	public  String MSTA_DO_INIT;
	public  String MSTA_CONNECTION_URL = null;
	public int MSTA_CONNECTION_TIMEOUT = 100000;
	public int MSTA_RESPONSE_TIMEOUT = 100000;
	public int MSTA_TIMEOUT_WAIT = 3000;
	public int MSTA_TRIES =  3;	
	
	public  String microserviceName = null;
	public  String microserviceId = null;
	public  String instanceId = null;
	//public  String MyURI = null;
	public  String buildKey = null;
	public  String deploymentKey = null;
	
	//the in memory hash map of all things MST-AUTH
	public Semaphore listsemaphore;
	public LinkedHashMap<String, JSONObject> graphname_to_auth = null;
	public LinkedHashMap<String, PublicKey> graphname_to_public = null;
	//public  String GraphUID = null;
	
	byte[] decodepublic;
    //X509EncodedKeySpec ks3 =  new X509EncodedKeySpec(decodepublic);
    //KeyFactory kf3 = KeyFactory.getInstance("RSA");
    //PublicKey publicKey = kf3.generatePublic(ks3);
	
	public byte[] decryptedprivate;
	//PKCS8EncodedKeySpec ks2 =  new PKCS8EncodedKeySpec(decryptedprivate);
    //KeyFactory kf2 = KeyFactory.getInstance("RSA");
    //PrivateKey privateKey = kf2.generatePrivate(ks2);
	
	// synch
	MST_Auth_BaseWebsocket mylistener; 



	// *******************************************************************
	// 
	// all things authorization
	//
	// used by both SEND and RECEIVE
	// to check if this type of communication is authorized
	//
	// *******************************************************************
	static public int CheckAuthorization(JSONObject GraphObject, String direction, String type,  String InboundMethod) {
	    //System.out.println("My name: " + MyMicroserviceName + " Graph Name: " + service + " type: " + type);
		//JSONObject GraphObject = graphname_to_auth.get(service);
	    //System.out.println(GraphObject.toString());
		if (GraphObject == null) return 0;
	    JSONArray GraphAuth = GraphObject.getJSONArray("authorizations");
	    int authorized = 0;
	    // loop through graph
	    for (int i = 0; i < GraphAuth.length(); i++) { 
	    	JSONObject graphauths = GraphAuth.getJSONObject(i); 
	    	if(graphauths.has(direction)) {
	    		JSONArray Auths = graphauths.getJSONArray(direction);
	    		// loop through authorizations
	    	    for (int y = 0; y < Auths.length(); y++) { 
	    	    	// auth must equal type 
	    	    	if (Auths.get(y).equals(type) || Auths.get(y).equals("*")) authorized = 1;
	    	    	// or equal * if RECEIVE
	    	    	//else if (direction.equals("RECEIVE") && Auths.get(y).equals("*")) authorized = 1;	    	    		
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
	
	public void HandleException(String e) {
		// to do add communication to server
	    System.out.println(e);		
	}
}
