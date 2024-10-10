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
            SSLParameters params = new SSLParameters();
            params.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(params);
            socket.setSoTimeout(5000);

            socket.startHandshake(); // explicit TLS handshake
            System.out.println("Handshake successful!");

            try (PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                 InputStream in = socket.getInputStream()) {

                out.println(fileName); // Send the filename to the server

                // Create the output file with an underscore prefix
                String outputFileName = "_" + fileName;
                try (FileOutputStream fileOut = new FileOutputStream(outputFileName)) {
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = in.read(buffer)) != -1) {
                        fileOut.write(buffer, 0, bytesRead);
                    }
                }

                System.out.println("File received and saved as " + outputFileName);
            }

            // Get the server's certificate and verify the hostname
            SSLSession session = socket.getSession();
            X509Certificate cert = (X509Certificate) session.getPeerCertificates()[0];
            String serverCN = getCommonName(cert);
            System.out.println("Server CN: " + serverCN);
            if (!host.equalsIgnoreCase(serverCN)) {
                throw new SSLException("Hostname verification failed!");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    // try {
    //   SSLSocketFactory factory = (SSLSocketFactory)SSLSocketFactory.getDefault();
    //   socket = (SSLSocket)factory.createSocket(host, port);

    //   // set HTTPS-style checking of HostName _before_ 
    //   // the handshake
    //   SSLParameters params = new SSLParameters();
    //   params.setEndpointIdentificationAlgorithm("HTTPS"); //Enables hostname validation
    //   socket.setSSLParameters(params);

    //   //Set a timeout
    //   socket.setSoTimeout(5000);

    //   socket.startHandshake(); // explicitly starting the TLS handshake
    //   System.out.println("Handshake successful!");

    //   // Perform I/O after the handshake (communicating with the server)
    //   try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
    //   PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

    //     // Send the file name to the server
    //     out.println(file);

    //     // Read and print the server's response
    //     String response = in.readLine();
    //     if (response != null) {
    //         System.out.println("Received from server: " + response);
    //     } else {
    //         System.out.println("No response received from the server.");
    //     }
    //   }

    //   // get the X509Certificate for this session
    //   SSLSession session = socket.getSession();
    //   X509Certificate cert = (X509Certificate) session.getPeerCertificates()[0];

    //   // extract the CommonName, and then compare
    //   String serverCN = getCommonName(cert);
    //   System.out.println("Server CN: " + serverCN);

    //   if (!host.equalsIgnoreCase(serverCN)) {
    //     throw new SSLException("Hostname verification failed!");
    //   }
    // } catch (Exception e) {
    //   e.printStackTrace();
    // }
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
