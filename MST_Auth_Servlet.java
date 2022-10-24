package mst_auth_library;

import java.io.IOException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * mst_auth_servlet is a simple client side java servlet for the MST-Auth platform
 * hopefully allows easy expansion to other languages
 * 
 * Implements (forwards to the main mst_auth_library class):
 * 	  init
 *    doGet
 *    doPut
 *    doPost
 *    doDelete
 * 
 * @author mlbernardoni
 *
 */

/**
 * Servlet implementation class mst_auth_servlet
 */
@WebServlet("/MST_Auth_Servlet")
public class MST_Auth_Servlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public MST_Auth_Servlet() {
        super();
    }

    private MST_Auth_Library MSTA_Library;
	/**
	 * @see Servlet#init(ServletConfig)
	 */
	public void init(ServletConfig config) throws ServletException {
		MSTA_Library = new MST_Auth_Library();
		MSTA_Library.MST_Auth_Init();
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		MSTA_Library.doGet(request, response);
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		MSTA_Library.doPost(request, response);
	}

	/**
	 * @see HttpServlet#doPut(HttpServletRequest, HttpServletResponse)
	 */
	protected void doPut(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		MSTA_Library.doPut(request, response);
	}

	/**
	 * @see HttpServlet#doDelete(HttpServletRequest, HttpServletResponse)
	 */
	protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		MSTA_Library.doDelete(request, response);
	}

}
