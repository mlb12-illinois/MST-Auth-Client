package mst_auth_library;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONException;
import org.json.JSONObject;

import mst_auth_library.MSTAException;
import mst_auth_library.MST_Auth_BaseClientWrapper;
import mst_auth_library.MST_Auth_BaseServlet;
import mst_auth_library.MST_Auth_ClientWrapper;
import mst_auth_library.MST_Auth_Servlet;

//*******************************************************************
//*******************************************************************
//*******************************************************************
//
// This is the class the microservice is derived from
//
// It handles the handshake 
//
//*******************************************************************
//*******************************************************************
//*******************************************************************

public class MST_Auth_Microservice {
	protected MST_Auth_BaseClientWrapper msta_library;
	//public Semaphore mysemaphore;	
	public MST_Auth_Microservice() {
	}
	public void SetLibrary (MST_Auth_BaseClientWrapper MSTALibrary ) {
		msta_library = MSTALibrary;			
	}
	
	public void doGet(HttpServletRequest request, HttpServletResponse response, String trustedbody) throws IOException, MSTAException {
		System.out.println("base boo doGet");
	    response.getWriter().append("doGet Served at: ").append(request.getContextPath());
	}
	public void doPost(HttpServletRequest request, HttpServletResponse response, String trustedbody) throws IOException, MSTAException {
		System.out.println("base boo doPost");
	  	//mysemaphore = new Semaphore(1);	// if doing SendRequestA() use Semaphore and callbackResponse
	    response.getWriter().append("doPost Served at: ").append(request.getContextPath());
	}
	public void doPut(HttpServletRequest request, HttpServletResponse response, String trustedbody) throws IOException, MSTAException {
		System.out.println("base boo doPut");
	    response.getWriter().append("doPut Served at: ").append(request.getContextPath());
	}
	public void doDelete(HttpServletRequest request, HttpServletResponse response, String trustedbody) throws IOException, MSTAException {
		System.out.println("base boo doDelete");
	    response.getWriter().append("doDelete Served at: ").append(request.getContextPath());
	}

	public void callbackResponse(HttpResponse<String> parmmstresponse) {
		/*
		try {
			mysemaphore.acquire();
			if (parmmstresponse != null)
		    	System.out.println(resp);   	
			mysemaphore.release();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		//System.out.println("callbackResponse2");
		 */
	}
}
