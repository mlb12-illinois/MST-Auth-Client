package mst_auth_library;

import mst_auth_client.MST_Auth_Client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.concurrent.TimeUnit;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class MST_Auth_Library {
	private int MSTA_CONNECTION_TIMEOUT = 10000;
	private int MSTA_RESPONSE_TIMEOUT = 10000;
	private int MSTA_TIMEOUT_WAIT = 3000;
	private int MSTA_TRIES = 3;
	private String MSTA_URL = "http://localhost:8080/MST-AUTH/Register.html";
	private MST_Auth_Client MST_Client;
	private HttpRequest.Builder mstauthbuilder;
	private String GraphUID;
	private String GraphName;
	private String MyMicroserviceName;
	private String MyMicroserviceID;
	private String MyURI;
	private String InboundMethod;

	private LinkedHashMap<String, JSONObject> graphname_to_obj;
	
	/**
	 * mst_auth_library MST_Auth_Init used to initialize an mst_auth_library servlet
	 * FOR NOW JUST READING FROM JSON IN WEB-INF
	 * HAVE TO ADD REGISTER TO SERVER
	 */
	protected void MST_Auth_Init()
	{
		InboundMethod = "";
		MST_Client = new MST_Auth_Client();
		MST_Client.SetLibrary(this);
		graphname_to_obj = new LinkedHashMap<String, JSONObject>();


		try {
			ClassLoader classLoader = Thread.currentThread().getContextClassLoader();           
			InputStream stream = classLoader.getResourceAsStream("../MSTAConfiguration.json");
			if (stream == null) {
			    System.out.println("MSTAConfiguration.json missing from WEB-INF folder");
				return;
			}
			ByteArrayOutputStream result = new ByteArrayOutputStream();
			byte[] buffer = new byte[1024];
			for (int length; (length = stream.read(buffer)) != -1; ) {
			     result.write(buffer, 0, length);
			}
			// StandardCharsets.UTF_8.name() > JDK 7
			JSONObject r2sconifg =  new JSONObject(result.toString("UTF-8"));
			MSTA_CONNECTION_TIMEOUT = r2sconifg.getInt("MSTA_CONNECTION_TIMEOUT");
			MSTA_RESPONSE_TIMEOUT = r2sconifg.getInt("MSTA_RESPONSE_TIMEOUT");
			MSTA_TIMEOUT_WAIT = r2sconifg.getInt("MSTA_TIMEOUT_WAIT");
			MSTA_TRIES = r2sconifg.getInt("MSTA_TRIES");
			MSTA_URL = r2sconifg.getString("MSTA_URL");
		} 
		catch (IOException e) {
	      System.out.println(e.toString());
		}
		
		// temp 
		// TO DO CALL TO MST-AUTH SERVER
    	String jsonstr = new String("{ \"MYUID\": \"e701e579-b276-4d3b-93e1-31c929dda26f\","
    			+ "\"MyName\": \"MSTGateway\","
    			+ "\"MyURI\": \"http://localhost:8080/CS598-Gateway/MSTAGateway.html\","
    			+ "\"MicroserviceGraph\":["
	    			+ "{\"GraphName\": \"MSTGateway\","
	    			+ "\"GraphID\": \"e701e579-b276-4d3b-93e1-31c929dda26f\","
	    			+ "\"GraphURI\": \"http://localhost:8080/CS598-BusinessService/MSTAGateway.html\", "
	    			+ "\"GraphAuthorizations\":[{\"RECEIVE\": [\"*\"]},{\"FORWARD\": [\"GET\", \"PUT\", \"POST\"]}]"	// receive "*" from outside
	    			+ "},"
	    			+ "{\"GraphName\": \"MSTABusiness\","
	    			+ "\"GraphID\": \"2d79dc19-18e5-4559-a302-8ef6c8df9615\","
	    			+ "\"GraphURI\": \"http://localhost:8080/CS598-BusinessService/MSTABusiness.html\", "
	    			+ "\"GraphAuthorizations\":[{\"FORWARD\": [\"GET\", \"PUT\", \"POST\"]}]"	// receive "*" from outside
	    			+ "},"
	    			+ "{\"GraphName\": \"MST_Auth\","
	    			+ "\"GraphID\": \"15350c89-a8af-40dd-bc0e-905af263da35\","
	    			+ "\"GraphURI\": \"http://localhost:8080/CS598-BusinessService/MST_Auth.html\", "
	    			+ "\"GraphAuthorizations\":[{\"SEND\": [\"POST\"]},{\"RECEIVE\": [\"POST\"]}]"	
	    			+ "}"
    			+ "]}" ); 	
	    System.out.println(jsonstr);
    	JSONObject jsonobj =  new JSONObject(jsonstr);
	    System.out.println(jsonobj.toString());
	    
	    MyMicroserviceName = jsonobj.getString("MyName");
	    MyMicroserviceID = jsonobj.getString("MYUID");
	    MyURI = jsonobj.getString("MyURI");
	    JSONArray  jsonms = jsonobj.getJSONArray("MicroserviceGraph");
	    for (int i = 0; i < jsonms.length(); i++) { 
	    	 JSONObject GraphObject = jsonms.getJSONObject(i);  
	    	 String graphname = GraphObject.getString("GraphName");
	    	 graphname_to_obj.put(graphname, GraphObject);
	    }
    	

	}
	
	/**
	* Inbound Routines
	*/
	private void CheckInboundHeader(HttpServletRequest request) {
		String mstaheader = request.getHeader("MST-AUTH");
		if (mstaheader == null) {
			// no header, so from outside
			GraphName = MyMicroserviceName;
			if ((CheckAuthorization("RECEIVE", "*") == 0)) {
		    	throw(new IllegalArgumentException ("Non MST-AUTH rest calls not avalable"));		
			}
		}	
	}
	
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		InboundMethod = "GET";
		CheckInboundHeader(request);
		// get our header
		MST_Client.doGet(request, response);
		InboundMethod = "";
	}
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		InboundMethod = "POST";
		CheckInboundHeader(request);
		MST_Client.doPost(request, response);
		InboundMethod = "";
	}
	protected void doPut(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		InboundMethod = "PUT";
		CheckInboundHeader(request);
		MST_Client.doPut(request, response);
		InboundMethod = "";
	}
	protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		InboundMethod = "DELETE";
		CheckInboundHeader(request);
		MST_Client.doDelete(request, response);
		InboundMethod = "";
	}

	/**
	* Outbound Routines
	*/
	private int CheckAuthorization(String direction, String type) {
	    System.out.println(GraphName);
		JSONObject GraphObject = graphname_to_obj.get(GraphName);
	    System.out.println(GraphObject.toString());
	    JSONArray GraphAuth = GraphObject.getJSONArray("GraphAuthorizations");
	    int authorized = 0;
	    for (int i = 0; i < GraphAuth.length(); i++) { 
	    	JSONObject graphauths = GraphAuth.getJSONObject(i); 
	    	if(graphauths.has(direction)) {
	    		JSONArray Auths = graphauths.getJSONArray(direction);
	    	    for (int y = 0; y < Auths.length(); y++) { 
	    	    	if (Auths.get(y).equals(type) || Auths.get(y).equals("*")) authorized = 1;	    	    		
	    	    }
	    	}
	    	
	    	// if direction = SEND and has FORWARD
	    	if(direction.equals("SEND") && graphauths.has("FORWARD")) {
	    		JSONArray Auths = graphauths.getJSONArray("FORWARD");
	    	    for (int z = 0; z < Auths.length(); z++) { 
		    		// and type = InboundMethod then good 
	    	    	if (Auths.get(z).equals(type) && type.equals(InboundMethod)) authorized = 1;	
	    	    }
	    	} 
	    }
	    return authorized;
	}
	
	public void SetMicroservice(String microservicename) {
		GraphName = microservicename;
		JSONObject GraphObject = graphname_to_obj.get(GraphName);
		GraphUID = GraphObject.getString("GraphURI");
		// to do look up the URI from the passed in name
		try {
			mstauthbuilder = HttpRequest.newBuilder()
				.uri(new URI(GraphUID))
				.timeout(Duration.ofMillis(MSTA_RESPONSE_TIMEOUT));
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	// after connect time out to wait for response		
	}
	
	public void SetMethodWithBodyString(String method, String body ) {	// "POST" "OY NEW BODY"
		if ((CheckAuthorization("SEND", method) == 0)) {
	    	throw(new IllegalArgumentException (method + " not avalable"));		
		}
		mstauthbuilder.method(method, HttpRequest.BodyPublishers.ofString(body));		
	}

	public void SetHeader(String name, String value ) {	// "POST" "OY NEW BODY"
		mstauthbuilder.header(name, value);	// mstauthbuilder.header("Content-Type", "application/json; utf-8");
	}

	public HttpResponse SendRequest() {	// "POST" "OY NEW BODY"
	      // ADD the MST-AUTH header
		  mstauthbuilder.header("MST_AUTH", "OY");
		  
		  HttpRequest mstrequest = mstauthbuilder.build();
		  
		  
		  HttpClient mstclient = HttpClient.newBuilder()
			      .connectTimeout(Duration.ofMillis(MSTA_CONNECTION_TIMEOUT))	// time out to connect
			      .build();

		  int mytries = MSTA_TRIES;
		  int retcode = 200;
		  String errorstring;
		  errorstring = "";
		  try 
		  {
			  System.out.println("CLIENT SENDING");			  
			  HttpResponse<String> mstresponse = mstclient.send(mstrequest, BodyHandlers.ofString());
			  System.out.println("CLIENT SENT");
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
			  System.out.println("R2s Send Exception: " + e.toString());
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
  
  	    
