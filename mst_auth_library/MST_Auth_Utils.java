package mst_auth_library;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.LinkedHashMap;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONArray;
import org.json.JSONObject;

public class MST_Auth_Utils {
	public  String MSTA_DO_INIT;
	public  String MSTA_REST_URL = null;
	public  String MSTA_CONNECTION_URL = null;
	public  String GraphUID = null;
	public  String MyMicroserviceName = null;
	public  String MyMicroserviceID = null;
	public  String MyInstanceID = null;
	public  String MyURI = null;
	//the in memory hash map of all things MST-AUTH
	public LinkedHashMap<String, JSONObject> graphname_to_auth = null;
	public LinkedHashMap<String, PublicKey> graphname_to_public = null;
	
	byte[] decodepublic;
    //X509EncodedKeySpec ks3 =  new X509EncodedKeySpec(decodepublic);
    //KeyFactory kf3 = KeyFactory.getInstance("RSA");
    //PublicKey publicKey = kf3.generatePublic(ks3);
	
	public byte[] decryptedprivate;
	//PKCS8EncodedKeySpec ks2 =  new PKCS8EncodedKeySpec(decryptedprivate);
    //KeyFactory kf2 = KeyFactory.getInstance("RSA");
    //PrivateKey privateKey = kf2.generatePrivate(ks2);



	// *******************************************************************
	// 
	// all things authorization
	//
	// used by both SEND and RECEIVE
	// to check if this type of communication is authorized
	//
	// *******************************************************************
	public int CheckAuthorization(JSONObject GraphObject, String direction, String type,  String InboundMethod) {
	    //System.out.println("My name: " + MyMicroserviceName + " Graph Name: " + service + " type: " + type);
		//JSONObject GraphObject = graphname_to_auth.get(service);
	    //System.out.println(GraphObject.toString());
		if (GraphObject == null) return 0;
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
