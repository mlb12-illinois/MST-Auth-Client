package mst_auth_library;

import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

public class MST_Auth_BaseWebsocket implements WebSocket.Listener {
	MST_Auth_BaseWebsocket (MST_Auth_Servlet parmmyservlet) {
		myservlet = parmmyservlet;
	}
	MST_Auth_BaseWebsocket () {
		myservlet = null;
	}
	protected WebSocket mywebSocket;
	protected MST_Auth_Servlet myservlet;
	private CompletableFuture<String> responseFuture = null;
	
    public void onOpen(WebSocket webSocket) {
		//System.out.println("WebSocket connected");
		mywebSocket = webSocket;

        WebSocket.Listener.super.onOpen(webSocket);
    }

    public void onError(WebSocket webSocket, Throwable error) {
        //logger.info("ERROR");
    	mywebSocket = null;
		System.out.println("WebSocket onError " + error);

        WebSocket.Listener.super.onError(webSocket, error);
    }

    public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {

		if ( responseFuture != null) {
			responseFuture.complete(data.toString());
	    	responseFuture = null;
		}
		else {
			if (myservlet != null)
				myservlet.AuthIncomingText(data.toString());			
		}
        return WebSocket.Listener.super.onText(webSocket, data, last);
    }

    public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
    	mywebSocket = null;

		System.out.println("WebSocket closed with status " + statusCode + " and reason " + reason);

        return WebSocket.Listener.super.onClose(webSocket, statusCode, reason);
    }
/*    
    public CompletionStage<?> onPing(WebSocket webSocket, ByteBuffer data) {
      	sendPong(data);
        return WebSocket.Listener.super.onPing(webSocket, data);
   }
    
    public CompletionStage<?> onPong(WebSocket webSocket, ByteBuffer data) {
     	sendPong(data);
   	
        return WebSocket.Listener.super.onPong(webSocket, data);
   }
 */ 
    public void Close (int code, String reason)
    {
        if (mywebSocket != null && !mywebSocket.isOutputClosed()) {
        	mywebSocket.sendClose(code, reason);
        }
     }
   // SendText just sends
    public void SendText (String sendtext)
    {
        if (mywebSocket != null && !mywebSocket.isOutputClosed()) {
        	mywebSocket.sendText(sendtext, true);
        }
     }
    // SendMsg waits for response
    public String SendMsg (String sendtext, int msgtimeout)
    {
    	responseFuture = null;
    	String ret = null;
        try {
	        if (mywebSocket != null && !mywebSocket.isOutputClosed()) {
	            //CompletableFutures can only be "used" once, so create a new object
	    		//responseFuture = CompletableFuture.supplyAsync(null);
	    		responseFuture = new CompletableFuture<String>();
	        	mywebSocket.sendText(sendtext, true);

	        	//ret = responseFuture.orTimeout(msgtimeout, TimeUnit.MICROSECONDS).get();
	    		//System.out.println("WebSocket timeout " + msgtimeout );
	    		//System.out.println("WebSocket completableFuture " + completableFuture );
	        	ret = responseFuture.orTimeout(msgtimeout/10000, TimeUnit.SECONDS).get();
	    		//System.out.println("WebSocket ret " + ret );
	        	 
	        	responseFuture = null;
	        	
	       }
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
        	mywebSocket.sendClose(600, "MST-Auth Server Timed Out");
	    	throw(new NullPointerException ("MST-Auth Server webSocked Failed"));		
		}
        return ret;
     }
   
    public void SendClose (int code, String sendtext)
    {
        if (mywebSocket != null && !mywebSocket.isOutputClosed()) {
        	mywebSocket.sendClose(code, sendtext);
        }
     }
 /*   
    public void sendPing (String sendtext) {
        if (mywebSocket != null && !mywebSocket.isOutputClosed()) {
        	mywebSocket.sendPing(ByteBuffer.wrap(sendtext.getBytes()));   
        }
    }
    public void sendPing (ByteBuffer sendtext) {
        if (mywebSocket != null && !mywebSocket.isOutputClosed()) {
        	mywebSocket.sendPing(sendtext);  
        }
    }
    
    private void sendPong (ByteBuffer sendtext) {
        if (mywebSocket != null && !mywebSocket.isOutputClosed()) {
        	mywebSocket.sendPong(sendtext); 
        }
    }
    */
 }