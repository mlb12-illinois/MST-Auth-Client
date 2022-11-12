package mst_auth_library;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.datastax.driver.core.Cluster;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import com.datastax.driver.core.Session;
import com.datastax.driver.core.SimpleStatement;
import com.datastax.driver.core.Statement;


//*******************************************************************
//*******************************************************************
//*******************************************************************
//
// This is the class who's main function is the start up handshake
// 	with the wrapper
//
// At doGet etc, creates the MST-Auth verison of the wrapper 
//		MST_Auth_ClientWrapper
//
// The clients derived version of this only has to override GetService ()
//
//*******************************************************************
//*******************************************************************
//*******************************************************************

public class MST_Auth_ClientServlet extends MST_Auth_Servlet {
	//MST_Auth_ClientWrapper wrapper;
	
	
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
	    //System.out.println("OY1 MST_Auth_ClientServlet : " + MSTAUtils);

		MST_Auth_ClientWrapper wrapper = new MST_Auth_ClientWrapper(MSTAUtils, this);
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

		MST_Auth_ClientWrapper wrapper = new MST_Auth_ClientWrapper(MSTAUtils, this);
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
		MST_Auth_ClientWrapper wrapper = new MST_Auth_ClientWrapper(MSTAUtils, this);
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
		MST_Auth_ClientWrapper wrapper = new MST_Auth_ClientWrapper(MSTAUtils, this);
		wrapper.SetClient(GetService());
		try {
			wrapper.doDelete(request, response);
		} catch (Exception e) {
			e.printStackTrace();
			MSTAUtils.HandleException(e.toString());
		}
		wrapper = null;
	}
}
