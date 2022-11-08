package mst_auth_library;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Phaser;
import java.util.concurrent.TimeUnit;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONException;

//import mst_auth_client.MST_Auth_Client;

public class MST_Auth_BaseServlet extends HttpServlet {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	protected MST_Auth_Utils MSTAUtils = null;
	protected int MSTA_CONNECTION_TIMEOUT = 100000;;
	protected int MSTA_RESPONSE_TIMEOUT = 100000;
	protected int MSTA_TIMEOUT_WAIT = 3000;
	protected int MSTA_TRIES =  3;	
	
	protected Phaser phaser = null;
	//protected HttpRequest.Builder mstauthbuilder;

	public void init(ServletConfig config) throws ServletException {
		MSTAUtils = new MST_Auth_Utils();		
	}
	public void destroy() {
	}
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		MST_Auth_BaseClientWrapper wrapper = new MST_Auth_BaseClientWrapper(MSTAUtils, MSTA_CONNECTION_TIMEOUT, MSTA_RESPONSE_TIMEOUT, MSTA_TIMEOUT_WAIT, MSTA_TRIES);
		try {
			wrapper.doGet(request, response, null);
		} catch (IOException e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		} catch (MSTAException e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}	
		wrapper = null;
	}
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		MST_Auth_BaseClientWrapper wrapper = new MST_Auth_BaseClientWrapper(MSTAUtils, MSTA_CONNECTION_TIMEOUT, MSTA_RESPONSE_TIMEOUT, MSTA_TIMEOUT_WAIT, MSTA_TRIES);
		try {
			wrapper.doPost(request, response, null);
		} catch (IOException e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		} catch (MSTAException e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}			
		wrapper = null;
	}
	protected void doPut(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		MST_Auth_BaseClientWrapper wrapper = new MST_Auth_BaseClientWrapper(MSTAUtils, MSTA_CONNECTION_TIMEOUT, MSTA_RESPONSE_TIMEOUT, MSTA_TIMEOUT_WAIT, MSTA_TRIES);
		try {
			wrapper.doPut(request, response, null);
		} catch (IOException e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		} catch (MSTAException e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}			
		wrapper = null;
	}
	protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		MST_Auth_BaseClientWrapper wrapper = new MST_Auth_BaseClientWrapper(MSTAUtils, MSTA_CONNECTION_TIMEOUT, MSTA_RESPONSE_TIMEOUT, MSTA_TIMEOUT_WAIT, MSTA_TRIES);
		try {
			wrapper.doPut(request, response, null);
		} catch (IOException e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		} catch (MSTAException e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}			
		wrapper = null;
	}
	
//	public void CassandraLog(String str) {
//		System.out.println("OYBase " + str);

//	}
}

