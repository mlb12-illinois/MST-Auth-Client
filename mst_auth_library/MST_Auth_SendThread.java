package mst_auth_library;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.net.http.WebSocket;
import java.net.http.WebSocket.Listener;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Phaser;
import java.util.concurrent.TimeUnit;

import org.json.JSONException;

public class MST_Auth_SendThread implements  Runnable { 
	protected Phaser phaser = null;
	protected MST_Auth_Utils MSTAUtils;
	protected MST_Auth_BaseClientWrapper ServletReturn = null;
	protected MST_Auth_Servlet AuthReturn = null;
	HttpRequest.Builder mstauthbuilder = null;

	// asynch send to other microservice
	MST_Auth_SendThread(MST_Auth_Utils parmMSTAUtils, HttpRequest.Builder parmmstauthbuilder, MST_Auth_BaseClientWrapper paramServletReturn, Phaser parmphaser)  {
		mstauthbuilder = parmmstauthbuilder;
		phaser = parmphaser;
		ServletReturn = paramServletReturn;
		MSTAUtils = parmMSTAUtils;
	}
	
	// asynch send to MST-Auth
	MST_Auth_SendThread(MST_Auth_Utils parmMSTAUtils, HttpRequest.Builder parmmstauthbuilder, MST_Auth_Servlet parmAuthReturn)  {
		mstauthbuilder = parmmstauthbuilder;
		MSTAUtils = parmMSTAUtils;
		AuthReturn = parmAuthReturn;
	}
	
    public void run(){
    	HttpRequest mstrequest = null;
	    mstrequest = mstauthbuilder.build();
	  
	  // config the client
	  HttpClient mstclient = HttpClient.newBuilder()
		      .connectTimeout(Duration.ofMillis(MSTAUtils.MSTA_CONNECTION_TIMEOUT))	// time out to connect
		      .build();

	  // get ready for send
	  int mytries = MSTAUtils.MSTA_TRIES;
	  int retcode = 200;
	  String errorstring;
	  errorstring = "";
	  try 
	  {
		  while (mytries > 0) 
		  {
			  try
			  {
				  // test sending to websocket
				  // config the client
				  
				  // do the acutal send
				  //System.out.println("Entering SendRequestA");
				  //System.out.println("CLIENT SENDING");			  
				  CompletableFuture<HttpResponse<String>> mstresponseF = mstclient.sendAsync(mstrequest, BodyHandlers.ofString());
				  //System.out.println("CLIENT SENT");
				  HttpResponse<String> mstresponse = mstresponseF.get();
				  //TimeUnit.MILLISECONDS.sleep(5000);
				  //System.out.println("Leaving SendRequestA");
				  //System.out.println(mstresponse);
				  //phaser.arrive(); 
				  retcode = mstresponse.statusCode();
				  if (retcode != 200 ) {
					  errorstring = ( "Sendthread Response: " + mstresponse.body() + "; retcode: " + retcode);
					  //System.out.println(errorstring );
					  mytries--;
					  if (mytries > 0) {
						  try {
							  TimeUnit.MILLISECONDS.sleep(MSTAUtils.MSTA_TIMEOUT_WAIT);	// add a little wait, to see if root will end
						  }
						  catch (JSONException | InterruptedException ie) {
							  throw(new MSTAException (": InterruptedException" + ie));		
						  }						  
					  }
					  else {
						  if ( ServletReturn != null) ServletReturn.callbackResponse(null);
						  return;
					  }
					  //phaser.arriveAndDeregister();
				  }
				  else {
					  //errorstring = ( "Sendthread Response: " + retcode);
					  //System.out.println(errorstring );
					  // 200 so good
					  if ( ServletReturn != null) ServletReturn.callbackResponse(mstresponse);
					  if ( AuthReturn != null) AuthReturn.AuthCallbackResponse(mstresponse);
					  //phaser.arriveAndDeregister();
					  
					  return;
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
						  System.out.println(errorstring);
					  }
				  }
				  else {
					  //if ( ServletReturn != null) ServletReturn.callbackResponse(null );
					  //if ( AuthReturn != null) AuthReturn.AuthCallbackResponse(null);
					  return;
				  }
			  }	   
		  }
      }
	  finally { // Very important to wrap
		  if (phaser != null) phaser.arriveAndDeregister();
	  }
	  //
    }
}
