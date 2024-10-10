//Name: Justin Poutoa
//ID: 1620107

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.KeyStore;
import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class MyTLSFileServer {

   private static ServerSocketFactory getSSF() throws Exception{
      // Get 
      //    an SSL Context that speaks some version of TLS, 
      //    a KeyManager that can hold certs in X.509 format,  
      //    and a JavaKeyStore (JKS) instance   
      SSLContext ctx = SSLContext.getInstance("TLS");
      KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
      KeyStore ks = KeyStore.getInstance("JKS");

      //Declare a fileinputstream
      FileInputStream keyStoreFile = new FileInputStream("server.jks");

      // Store the passphrase to unlock the JKS file.   
      // INSECURE! DON'T DO IT.
      char[] passphrase = "user_like_them".toCharArray();

      // Load the keystore file. The passphrase is   
      // an optional parameter to allow for integrity   
      // checking of the keystore. Could be null   
      ks.load(keyStoreFile, passphrase);

      // Init the KeyManagerFactory with a source   
      // of key material. The passphrase is necessary   
      // to unlock the private key contained.   
      kmf.init(ks, passphrase);

      // initialise the SSL context with the keys.   
      ctx.init(kmf.getKeyManagers(), null, null);

      // Get the factory we will use to create   
      // our SSLServerSocket   
      SSLServerSocketFactory ssf = ctx.getServerSocketFactory();
      return ssf;
   }

   public static void main(String args[]){ 
      try {
         // use the getSSF method to get a  SSLServerSocketFactory and 
         // create our  SSLServerSocket, bound to specified port  
         ServerSocketFactory ssf = getSSF(); 
         SSLServerSocket ss =  (SSLServerSocket) ssf.createServerSocket(50202); 
         String EnabledProtocols[] = {"TLSv1.2", "TLSv1.3"}; 
         ss.setEnabledProtocols(EnabledProtocols); 
         
         System.out.println("Server is listening on port 50202...");

         //Continuosly accept client connections
         while(true){
            //Accept an incoming connection
            SSLSocket s = (SSLSocket)ss.accept();
            handleClient(s);
         }
      } catch (Exception e) {
         e.printStackTrace();
      }
   }

   /**
    * Method to handle communication with the connected client.
    * @param socket the socket used to communicate with client
    */
   private static void handleClient(SSLSocket socket){
      try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
         OutputStream out = socket.getOutputStream()){

         //Read the requested file from the client
         String filename = in.readLine();
         File file = new File(filename); //creating a file object for it

         //Checks if the file exists; if not, close the connection as per instructions.
         if(!file.exists() || file.isDirectory()){
            System.out.println("Requested file does not exist or is a directory. Closing connection.");
            socket.close();
            return;
         }

         //Send file content to the client
         byte[] buffer = new byte[4096]; //buffer to hold the chunks of data
         try(FileInputStream fileIn = new FileInputStream(file)){
            int bytesRead;
            //Read and send the file in chunks and write to output
            while((bytesRead = fileIn.read(buffer)) != -1){
               out.write(buffer, 0, bytesRead);
            }
         }

         System.out.println("File " + filename + " sent to client.");
      } catch(IOException e){
         e.printStackTrace();
      } finally{
         try{
            socket.close();
         } catch(IOException e){
            e.printStackTrace();
         }
      }
   }
}
