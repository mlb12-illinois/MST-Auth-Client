package mst_auth_library;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.concurrent.Phaser;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONException;

import mst_auth_client.MST_Auth_Client;

public class MST_Auth_BaseClientWrapper {
	protected MST_Auth_Client MST_Client;
	protected MST_Auth_Utils MSTAUtils;
	protected int MSTA_CONNECTION_TIMEOUT;
	protected int MSTA_RESPONSE_TIMEOUT;
	protected int MSTA_TIMEOUT_WAIT;
	protected int MSTA_TRIES;	
	
	protected Phaser phaser;
	protected HttpRequest.Builder mstauthbuilder;

	public MST_Auth_BaseClientWrapper(MST_Auth_Utils parmMSTAUtils, int parmMSTA_CONNECTION_TIMEOUT, int parmMSTA_RESPONSE_TIMEOUT, int parmMSTA_TIMEOUT_WAIT,  int parmMSTA_TRIES) {
		MSTAUtils = parmMSTAUtils;
		MSTA_CONNECTION_TIMEOUT = parmMSTA_CONNECTION_TIMEOUT;;
		MSTA_RESPONSE_TIMEOUT = parmMSTA_RESPONSE_TIMEOUT;
		MSTA_TIMEOUT_WAIT = parmMSTA_TIMEOUT_WAIT;
		MSTA_TRIES =  parmMSTA_TRIES;		
		MST_Client = new MST_Auth_Client();
		MST_Client.SetLibrary(this);
	}
	
	public void doGet(HttpServletRequest request, HttpServletResponse response, String decryptedbody) throws IOException, MSTAException {
		    mstauthbuilder = HttpRequest.newBuilder();
			MST_Client.doGet(request, response, null);			
	}
	public void doPost(HttpServletRequest request, HttpServletResponse response, String decryptedbody) throws IOException, MSTAException  {
	        mstauthbuilder = HttpRequest.newBuilder();
			MST_Client.doPost(request, response, null);			
	}
	public void doPut(HttpServletRequest request, HttpServletResponse response, String decryptedbody) throws IOException, MSTAException  {
        	mstauthbuilder = HttpRequest.newBuilder();
			MST_Client.doPut(request, response, null);			
	}
	public void doDelete(HttpServletRequest request, HttpServletResponse response, String decryptedbody) throws IOException, MSTAException  {
        	mstauthbuilder = HttpRequest.newBuilder();
			MST_Client.doDelete(request, response, null);			
	}
	public void SetMicroservice(String microservicename) throws MSTAException {
		//RequestURI = (microservicename);
		 //System.out.println("SetMicroservice");

		try {
			mstauthbuilder
				.uri(new URI(microservicename))
				.timeout(Duration.ofMillis(MSTA_RESPONSE_TIMEOUT));
		} 
		catch (URISyntaxException e) {
			e.printStackTrace();
		}

	}
	public void SetMethodWithBodyString(String method, String body ) throws MSTAException {	
		 //System.out.println("SetMethodWithBodyString");
		//RequestMethod = (method);
		//RequestBody = (body);
		mstauthbuilder.method(method, HttpRequest.BodyPublishers.ofString(body));		
	}
	public void SetHeader(String name, String value ) {	
		 //System.out.println("SetHeader");
		//List<String> templist = new ArrayList<>();
		//templist.add(name);
		//templist.add(value);
		//RequestHeaders.add(templist);
		
		mstauthbuilder.header(name, value);	// example mstauthbuilder.header("Content-Type", "application/json; utf-8");
	}
	public void WaitA() {	
		//System.out.println("Entering WaitA");
		phaser.arriveAndAwaitAdvance();
		//System.out.println("Leaving WaitA");
	}
	
	public void SendRequestA() throws MSTAException {	
	  if (phaser == null) phaser = new Phaser(1);
	  phaser.register();	
	    //List<List<String>> listCopy = new ArrayList<List<String>>(RequestHeaders);
	  //RequestHeaders = new ArrayList<>();

	  MST_Auth_SendThread T1 = new MST_Auth_SendThread(MSTAUtils, MSTA_CONNECTION_TIMEOUT, MSTA_RESPONSE_TIMEOUT, MSTA_TIMEOUT_WAIT, MSTA_TRIES, phaser, mstauthbuilder, this);
	  Thread t = new Thread (T1, "SendThread");					  
      t.start();
	  mstauthbuilder = HttpRequest.newBuilder();
	  
	}
	public void callbackResponse(HttpResponse<String> mstresponse) {
		//System.out.println("callbackResponse");
		MST_Client.callbackResponse(mstresponse);
	}
	
	public HttpResponse<String> SendRequest() throws MSTAException {	
	  //System.out.println("SendRequest");
	  HttpRequest mstrequest = mstauthbuilder.build();
	  
	  // config the client
	  HttpClient mstclient = HttpClient.newBuilder()
		      .connectTimeout(Duration.ofMillis(MSTA_CONNECTION_TIMEOUT))	// time out to connect
		      .build();
	  mstauthbuilder = HttpRequest.newBuilder();
	  //System.out.println("built");

	  // get ready for send
	  int mytries = MSTA_TRIES;
	  int retcode = 200;
	  String errorstring;
	  errorstring = "";
	  while (mytries > 0)
	  {
		  //System.out.println("Synch mytries" );
		  try 
		  {
			  // do the acutal send
			  
			  //System.out.println("CLIENT SENDING");			  
			  HttpResponse<String> mstresponse = mstclient.send(mstrequest, BodyHandlers.ofString());
			  //System.out.println("mstresponse");
			  //System.out.println("CLIENT SENT");
			  retcode = mstresponse.statusCode();
			  if (retcode != 200 ) {
				  errorstring = ( "Response: " + mstresponse.body() + "; retcode: " + retcode);
				  System.out.println(errorstring );
				  mytries--;
				  if (mytries > 0) {
					  try {
						  TimeUnit.MILLISECONDS.sleep(MSTA_TIMEOUT_WAIT);	// add a little wait, to see if root will end
					  }
					  catch (JSONException | InterruptedException ie) {
						  throw(new MSTAException (": InterruptedException" + ie));		
					  }						  
				  }
			  }
			  else {
				  // 200 so good
				  //System.out.println("200 so good");
				  ///System.out.println(mstresponse.body().toString());
				  return mstresponse;
			  } 
		  }
		  catch (Exception e) 
		  { 
			  errorstring = (errorstring + "Exception: " + e.toString() + ";");
			  System.out.println("MST-Auth Send Exception: " + e.toString());
			  mytries--;
			  if (mytries > 0) {
				  try {
					  TimeUnit.MILLISECONDS.sleep(MSTA_TIMEOUT_WAIT);	// add a little wait, to see if root will end
				  }
				  catch (JSONException | InterruptedException ie) {
					  errorstring = errorstring + "InterruptedException" + ie.toString() + ";";
				      throw(new MSTAException ("MST-Auth: InterruptedException" + errorstring));		
				  }
			  }
		  }
	  }
	  return null;
	}
	public void Audit(String str) {}
}
