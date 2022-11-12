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
import java.util.concurrent.Semaphore;
//import java.util.concurrent.Phaser;
import java.util.concurrent.TimeUnit;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONException;

//*******************************************************************
//*******************************************************************
//*******************************************************************
//
//This is the class who's main function is to:
//	Initialize the MSTAUtils function
//
//	Provide the GetService function (the clients servlet only needs to 
//		override this to establish the hooks between the clients
//		microservice and the framework
//
//Also at doGet etc, creates the base verison of the wrapper 
//	MST_Auth_BaseClientWrapper
//  Used by MST_Auth_BaseClientWrapper 
//		to create microservice calls without MST-Auth
//		useful if a microservice has to hit a generic webservice
//
//
//*******************************************************************
//*******************************************************************
//*******************************************************************

public class MST_Auth_BaseServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
	protected MST_Auth_Utils MSTAUtils = null;

	public void init(ServletConfig config) throws ServletException {
		MSTAUtils = new MST_Auth_Utils();		
		MSTAUtils.listsemaphore = new Semaphore(1);	
	}
	public void destroy() {
	}

	//*******************************************************************
	// the servlet in the clients code just has to override this
	//*******************************************************************
	public MST_Auth_Microservice  GetService () {		// *****  override this
		return new MST_Auth_Microservice();			
	}
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        //System.out.println(" MST_Auth_BaseServlet doGet ");
		
		MST_Auth_BaseClientWrapper wrapper = new MST_Auth_BaseClientWrapper(MSTAUtils);
		wrapper.SetClient(GetService());
		try {
			wrapper.doGet(request, response);
		} catch (Exception e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}	
		wrapper = null;
	}
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		MST_Auth_BaseClientWrapper wrapper = new MST_Auth_BaseClientWrapper(MSTAUtils);
		wrapper.SetClient(GetService());
		try {
			wrapper.doPost(request, response);
		} catch (Exception e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}			
		wrapper = null;
	}
	protected void doPut(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		MST_Auth_BaseClientWrapper wrapper = new MST_Auth_BaseClientWrapper(MSTAUtils);
		wrapper.SetClient(GetService());
		try {
			wrapper.doPut(request, response);
		} catch (Exception e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}			
		wrapper = null;
	}
	protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		MST_Auth_BaseClientWrapper wrapper = new MST_Auth_BaseClientWrapper(MSTAUtils);
		wrapper.SetClient(GetService());
		try {
			wrapper.doPut(request, response);
		} catch (Exception e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}			
		wrapper = null;
	}
	
}

