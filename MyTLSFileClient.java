//Name: Justin Poutoa
//ID: 1620107

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.security.cert.X509Certificate;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

public class MyTLSFileClient {
  public static void main(String args[])
  {
    if(args.length < 3){
      System.out.println("Usage = java MyTLSFileClient <hostname> <portnumber> <filename>");
      return;
    }

    //The server's hostname and port "lab-rg06-05.cms.waikato.ac.nz"   50202
    String host = args[0];
    int port = Integer.parseInt(args[1]);
    String fileName = args[2];

    try (SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(host, port)) {
      //Set parameters to enforce hostname verification
      SSLParameters params = new SSLParameters();
      //Enable hostname validation
      params.setEndpointIdentificationAlgorithm("HTTPS");
      socket.setSSLParameters(params);
      //Set a timeout
      socket.setSoTimeout(5000);

      socket.startHandshake(); //Explicitly start the TLS handshake
      System.out.println("Handshake successful!");

      //Perform I/O operations after handshake
      try (PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
          InputStream in = socket.getInputStream()) {

        out.println(fileName); //Send the filename to the server

        //Create the output file with an underscore prefix
        String outputFileName = "_" + fileName;
        try (FileOutputStream fileOut = new FileOutputStream(outputFileName)) {
          //Buffer for file data
          byte[] buffer = new byte[4096];
          int bytesRead;
          //Read data from server and write to output file
          while ((bytesRead = in.read(buffer)) != -1) {
            fileOut.write(buffer, 0, bytesRead);
          }
        }

        System.out.println("File received and saved as " + outputFileName);
      }

      //Get the server's certificate and verify the hostname
      SSLSession session = socket.getSession();
      X509Certificate cert = (X509Certificate) session.getPeerCertificates()[0];

      //Extract common name from certificate
      String serverCN = getCommonName(cert);
      System.out.println("Server CN: " + serverCN);

      //Verify that the server's CN matches the hostname provided
      if (!host.equalsIgnoreCase(serverCN)) {
        throw new SSLException("Hostname verification failed!");
      }
    } catch (Exception e) {
        e.printStackTrace();
    }
  }

  /**
   * Method to extract the Common Name (CN) from the X509 certificate.
   * @param cert
   * @return
   * @throws Exception
   */
  public static String getCommonName(X509Certificate cert) throws Exception{
    //Declare variables
    String cn = null;
    try {
      //Get the subject name
      String name = cert.getSubjectX500Principal().getName();
      //Parse the name into an LdapName object
      LdapName ln = new LdapName(name);
      //Search for the CN in the RDNs of the distinguished name
      for(Rdn rdn : ln.getRdns()) 
        if("CN".equalsIgnoreCase(rdn.getType()))
          //Get the value of the CN
          cn = rdn.getValue().toString();
    } catch (Exception e) {
      e.printStackTrace();
    }
    //Return the common name
    return cn;
  }
}
