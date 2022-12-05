package mst_auth_library;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.net.http.WebSocket.Listener;
import java.time.Duration;
import org.json.JSONObject;

public class MST_Auth_SendThreadWS implements  Runnable { 
	protected MST_Auth_Utils MSTAUtils;
	protected MST_Auth_Servlet AuthReturn = null;
	JSONObject putobj = null;

	
	// asynch send to MST-Auth
	MST_Auth_SendThreadWS(MST_Auth_Utils parmMSTAUtils, JSONObject parmobj, MST_Auth_Servlet parmAuthReturn)  {
		putobj = parmobj;
		MSTAUtils = parmMSTAUtils;
		AuthReturn = parmAuthReturn;
	}
	
    public void run(){
    	
    	MST_Auth_BaseWebsocket mylistener = new MST_Auth_BaseWebsocket();
		  
		try {
			
			HttpClient mstclient2 = HttpClient.newHttpClient();
			WebSocket mysocket;
				mysocket = mstclient2.newWebSocketBuilder()
						.connectTimeout(Duration.ofMillis(MSTAUtils.MSTA_CONNECTION_TIMEOUT))
				        .buildAsync(new URI(MSTAUtils.MSTA_CONNECTION_URL), mylistener)
				        .join();

				String rsp = mylistener.SendMsg(putobj.toString(),  MSTAUtils.MSTA_RESPONSE_TIMEOUT);
		   		mylistener.Close (200, "destroy");
				//System.out.println(rsp);
		    	AuthReturn.AuthCallbackResponse(rsp);
		} catch (Exception e) {
			e.printStackTrace();	
		}
    }
    	
 }
