// The client is usually much more straight forward
// Defaults will load Java’s set of Trusted Certificates
// Java will validate there is a path to a trusted CA
// By default, Java will NOT do hostname validation,
// but the more secure thing to do is to check!

// THE CODE BELOW IS INCOMPLETE AND HAS PROBLEMS
// FOR EXAMPLE, IT IS MISSING THE NECESSARY EXCEPTION HANDLING


import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.cert.X509Certificate;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

public class MyTLSFileClient {
  public static void main(String args[])
  {
    if(args.length != 2){
      System.out.println("Usage = java MyTLSFileClient <hostname> <portnumber> <filename>");
      return;
    }

    //The server's hostname and port "lab-rg06-05.cms.waikato.ac.nz"   50202
    String host = args[0];
    int port = Integer.parseInt(args[1]);

    try {
      SSLSocketFactory factory = (SSLSocketFactory)SSLSocketFactory.getDefault();
      SSLSocket socket = (SSLSocket)factory.createSocket(host, port);

      // set HTTPS-style checking of HostName _before_ 
      // the handshake
      SSLParameters params = new SSLParameters();
      params.setEndpointIdentificationAlgorithm("HTTPS"); //Enables hostname validation
      socket.setSSLParameters(params);

      socket.startHandshake(); // explicitly starting the TLS handshake

      //Perform I/O after the handshake (input/output)
      try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
          out.println("Hello, TLS Server!!!");
          String response = in.readLine();
          System.out.println("Received from server: " + response);
        }

      // get the X509Certificate for this session
      SSLSession session = socket.getSession();
      X509Certificate cert = (X509Certificate) session.getPeerCertificates()[0];

      // extract the CommonName, and then compare
      String serverCN = getCommonName(cert);
      System.out.println("Server CN: " + serverCN);

      if (!host.equalsIgnoreCase(serverCN)) {
        throw new SSLException("Hostname verification failed!");
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public static String getCommonName(X509Certificate cert) throws Exception{
    //Declare variables
    String cn = null;
    try {
      String name = cert.getSubjectX500Principal().getName();
      LdapName ln = new LdapName(name);
      // Rdn: Relative Distinguished Name
      for(Rdn rdn : ln.getRdns()) 
        if("CN".equalsIgnoreCase(rdn.getType()))
          cn = rdn.getValue().toString();
    } catch (Exception e) {
      e.printStackTrace();
    }
    //Return the string
    return cn;
  }
}
