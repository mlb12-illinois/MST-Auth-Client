package mst_auth_library;

import java.io.BufferedReader;
import java.io.IOException;
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
import java.util.UUID;
import java.util.concurrent.Phaser;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONException;
import org.json.JSONObject;

import com.datastax.driver.core.SimpleStatement;
import com.datastax.driver.core.Statement;

import mst_auth_client.MST_Auth_Client;

public class MST_Auth_ServerClientWrapper extends MST_Auth_ClientWrapper{
	protected MST_Auth_ServerServlet pServer;

	public MST_Auth_ServerClientWrapper(MST_Auth_Utils parmMSTAUtils, int parmMSTA_CONNECTION_TIMEOUT, int parmMSTA_RESPONSE_TIMEOUT, int parmMSTA_TIMEOUT_WAIT,  int parmMSTA_TRIES, MST_Auth_ServerServlet parampServlet) {
		super(parmMSTAUtils, parmMSTA_CONNECTION_TIMEOUT, parmMSTA_RESPONSE_TIMEOUT, parmMSTA_TIMEOUT_WAIT,  parmMSTA_TRIES);
		pServer = parampServlet;
		MST_Client.SetLibrary(this);
	}
	
	@Override
	public void Audit(String str) {
		//System.out.println(pServer);
		//System.out.println("OYCc " + str);
		pServer.CassandraLog(str);		
		//System.out.println("OYD ");
	}
	
	public void setClient() {
		MST_Client = new MST_Auth_Client();
		MST_Client.SetLibrary(this);		
	}


}
