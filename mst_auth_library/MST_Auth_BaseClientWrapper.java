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

//*******************************************************************
//*******************************************************************
//*******************************************************************
//
//This is the baseClient Wrapper
//
// all sends are done here (derived classes call this)
//
// Also at doGet etc, creates the base verison of the wrapper 
//		to create microservice calls without MST-Auth
//		useful if a microservice has to hit a generic webservice
//
//*******************************************************************
//*******************************************************************
//*******************************************************************

public class MST_Auth_BaseClientWrapper {
	protected MST_Auth_Microservice MST_Client;
	protected MST_Auth_Utils MSTAUtils;
	
	protected Phaser phaser;
	protected HttpRequest.Builder mstauthbuilder;

	public MST_Auth_BaseClientWrapper(MST_Auth_Utils parmMSTAUtils) {
		MSTAUtils = parmMSTAUtils;
	}
	
	public void SetClient(MST_Auth_Microservice client) {
		MST_Client = client;
		MST_Client.SetLibrary(this);
	}
	
	public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, MSTAException {
			MST_Client.doGet(request, response, null);			
	}
	public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, MSTAException  {
			MST_Client.doPost(request, response, null);			
	}
	public void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException, MSTAException  {
			MST_Client.doPut(request, response, null);			
	}
	public void doDelete(HttpServletRequest request, HttpServletResponse response) throws IOException, MSTAException  {
			MST_Client.doDelete(request, response, null);			
	}
	public void SetMicroservice(String microservicename) throws MSTAException {
		try {
		    mstauthbuilder = HttpRequest.newBuilder();
			mstauthbuilder
				.uri(new URI(microservicename))
				.timeout(Duration.ofMillis(MSTAUtils.MSTA_RESPONSE_TIMEOUT));
		} 
		catch (Exception e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}

	}
	public void SetMethodWithBodyString(String method, String body ) throws MSTAException {	
		mstauthbuilder.method(method, HttpRequest.BodyPublishers.ofString(body));		
	}
	public void SetHeader(String name, String value ) {	
		mstauthbuilder.header(name, value);	// example mstauthbuilder.header("Content-Type", "application/json; utf-8");
	}
	// *******************************************************************
	// *******************************************************************
	// *******************************************************************
	//
	//	Outbound stuff (used by all classes, including derived)
	//
	// *******************************************************************
	// *******************************************************************
	// *******************************************************************

	public void WaitA() {	
		phaser.arriveAndAwaitAdvance();
	}
	
	public void SendRequestA() throws MSTAException {	
	  if (phaser == null) phaser = new Phaser(1);
	  phaser.register();	

	  MST_Auth_SendThread T1 = new MST_Auth_SendThread(MSTAUtils, mstauthbuilder, this, phaser);
	  Thread t = new Thread (T1, "SendThread");					  
      t.start();
	  mstauthbuilder = HttpRequest.newBuilder();
	  
	}
	public void callbackResponse(HttpResponse<String> mstresponse) {
		//System.out.println("callbackResponse");
		MST_Client.callbackResponse(mstresponse);
	}
	
	public HttpResponse<String> SendRequest() throws MSTAException {	
	  //System.out.println("Base SendRequest1");
	  HttpRequest mstrequest = mstauthbuilder.build();
	  //System.out.println("Base SendRequest2");
	  
	  // config the client
	  HttpClient mstclient = HttpClient.newBuilder()
		      .connectTimeout(Duration.ofMillis(MSTAUtils.MSTA_CONNECTION_TIMEOUT))	// time out to connect
		      .build();
	  mstauthbuilder = HttpRequest.newBuilder();
	  //System.out.println("Base SendRequest3");

	  // get ready for send
	  int mytries = MSTAUtils.MSTA_TRIES;
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
			  //System.out.println("Base SendRequest4");
			  retcode = mstresponse.statusCode();
			  if (retcode != 200 ) {
				  errorstring = ( "Response: " + mstresponse.body() + "; retcode: " + retcode);
				  System.out.println(errorstring );
				  mytries--;
				  if (mytries > 0) {
					  try {
						  TimeUnit.MILLISECONDS.sleep(MSTAUtils.MSTA_TIMEOUT_WAIT);	// add a little wait, to see if root will end
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
					  TimeUnit.MILLISECONDS.sleep(MSTAUtils.MSTA_TIMEOUT_WAIT);	// add a little wait, to see if root will end
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

}
