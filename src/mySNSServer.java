import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;


public class mySNSServer {

	public static void main(String[] args) {
		System.out.println("servidor: main");
		mySNSServer server = new mySNSServer();
		server.startServer();
	}

	public void startServer() {
		ServerSocket sSoc = null;

		try {
			sSoc = new ServerSocket(23456);
		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		}

		while (true) {
			try {
				Socket inSoc = sSoc.accept();
				ServerThread newServerThread = new ServerThread(inSoc);
				newServerThread.start();
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
	}

	public static byte[] File_To_Array(File file) throws IOException {

		// Creating an object of FileInputStream to
		// read from a file
		FileInputStream fl = new FileInputStream(file);

		// Now creating byte array of same length as file
		byte[] arr = new byte[(int)file.length()];

		// Reading file content to byte array
		// using standard read() method
		fl.read(arr);

		// lastly closing an instance of file input stream
		// to avoid memory leakage
		fl.close();

		// Returning above byte array
		return arr;
	}

	public static void receiveFile(String fileName, String userDir, InputStream in, int fileSize) {

		System.out.println("   receiveFile: Função inicializada");

		OutputStream out = null;
		byte[] bytes = new byte[1024];

		try {
			out = new FileOutputStream("Servidor/"+userDir+"/"+fileName);
			int count;
			while (fileSize > 0 && (count = in.read(bytes, 0, (int)Math.min(bytes.length, fileSize))) != 1) {
				out.write(bytes, 0, count);
				fileSize -= count;
			}
			out.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		System.out.println("   receiveFile: Função Terminada");

	}

	public static void sendFile(InputStream in, OutputStream out) {

		System.out.println("   sendFile: Função inicializada");

		// Create a byte array to use as a buffer for reading from the InputStream
		byte[] bytes = new byte[1024];
		int count;
		try {
			// Read from the InputStream into the buffer until there are no more bytes to read
			while ((count = in.read(bytes)) > 0) {
				// Write the valid bytes (specified by the count variable) from the buffer to the OutputStream
				out.write(bytes, 0, count);
			}
		} catch (IOException e) {
			// Handle any IO errors that occur during the reading or writing process
			e.printStackTrace();
		}

		System.out.println("   sendFile: Função Terminada");
	}

	// Method which write the bytes into a file
	static void writeByte(byte[] bytes, File file) {
		try {

			// Initialize a pointer
			// in file using OutputStream
			OutputStream os = new FileOutputStream(file);

			// Starts writing the bytes in it
			os.write(bytes);

			// Close the file
			os.close();
		} catch (Exception e) {
			System.out.println("Exception: " + e);
		}
	}

	public String BytetoHex(byte[] arrayB){

		String HexString = "";
		for (byte b : arrayB) {
			String st = String.format("%02X", b);
			HexString +=st;
		}
		return HexString;
	}

	public byte[] HextoByte(String Hex){
		byte[] ans = new byte[Hex.length() / 2];
		for (int i = 0; i < ans.length; i++) {
			int index = i * 2;

			// Using parseInt() method of Integer class
			int val = Integer.parseInt(Hex.substring(index, index + 2), 16);
			ans[i] = (byte)val;
		}

		return ans;
	}

	class ServerThread extends Thread {

		private Socket socket = null;

		ServerThread(Socket inSoc) {
			socket = inSoc;
			System.out.println("mySNSServer: Thread do server para cada cliente");
		}

		public void run() {

			try {

				ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
				ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());

				String userCommand = (String)inStream.readObject();  //recebe comando -u ou -au ou não é reconhecido
				String userID = (String)inStream.readObject();  //recebe user ID
				String medico = (String)inStream.readObject();
				

				File diretorio = new File("Servidor/"+userID+"/");

				if(!diretorio.isDirectory()) {
					System.out.println("mySNSServer: Criando diretorio para utente "+userID);
					diretorio.mkdir();
				}
				
				if (userCommand.equals("-u")) {

					System.out.println("mySNSServer: Utilizador Reconhecido.");

					System.out.println("mySNSServer: Inicio de receber todos os ficheiros.");

					String command = (String) inStream.readObject();

					while (command.equals("-sc")) {

						System.out.println("mySNSServer:    Comando -sc reconhecido");

						String fileName = (String) inStream.readObject();
						System.out.println("mySNSServer: Nome do Ficheiro " + fileName);
						String fileSize = (String) inStream.readObject();
						System.out.println("mySNSServer:    tamanho, em bytes, do Ficheiro " + fileSize);

						File cifrado = new File("Servidor/"+userID+"/"+fileName);
						File chaveSecreta = new File("Servidor/"+userID+"/"+fileName);

						if (cifrado.exists() && chaveSecreta.exists()) {
							System.out.println("mySNSServer: Ficheiro cifrado e respectiva chave secreta existente");
							outStream.writeObject("False");
						} else {
							outStream.writeObject("True");
							InputStream in = socket.getInputStream();
							receiveFile(fileName, userID, in, Integer.valueOf(fileSize));
						}

						command = (String) inStream.readObject();

					}

					while (command.equals("-sa")) {

						System.out.println("mySNSServer:    Comando -sa reconhecido");

						String fileName = (String) inStream.readObject();
						System.out.println("mySNSServer: Nome do Ficheiro " + fileName);
						String fileSize = (String) inStream.readObject();
						System.out.println("mySNSServer:    tamanho, em bytes, do Ficheiro " + fileSize);

						File assinado = new File("Servidor/"+userID+"/"+fileName);
						File assinatura = new File("Servidor/"+userID+"/"+fileName);

						if (assinado.exists() && assinatura.exists()) {
							System.out.println("mySNSServer: Ficheiro assinado e respectiva assinatura existente");
							outStream.writeObject("False");
						} else {
							outStream.writeObject("True");
							InputStream in = socket.getInputStream();
							receiveFile(fileName, userID, in, Integer.valueOf(fileSize));
						}

						command = (String) inStream.readObject();
						System.out.println("Next command is: "+command);

					}

					while (command.equals("-se")) {

						System.out.println("mySNSServer:    Comando -se reconhecido");

						String fileName = (String) inStream.readObject();
						System.out.println("mySNSServer: Nome do Ficheiro " + fileName);
						String fileSize = (String) inStream.readObject();
						System.out.println("mySNSServer:    tamanho, em bytes, do Ficheiro " + fileSize);

						File seguro = new File("Servidor/"+userID+"/"+fileName);
						File seguroAssinatura = new File("Servidor/"+userID+"/"+fileName);
						File seguroChaveSecreta = new File("Servidor/"+userID+"/"+fileName);

						if (seguro.exists() && seguroAssinatura.exists() && seguroChaveSecreta.exists()) {
							System.out.println("mySNSServer: Ficheiro assinado e cifrado e respectiva assinatura e chave secreta existente");
							outStream.writeObject("False");
						} else {
							outStream.writeObject("True");
							InputStream in = socket.getInputStream();
							receiveFile(fileName, userID, in, Integer.valueOf(fileSize));
						}

						command = (String) inStream.readObject();

					}

					while (command.equals("-g")) {

						System.out.println("mySNSServer:    Comando -g reconhecido");

						String p = "Servidor/"+userID+"/";

						String fileName = (String) inStream.readObject();
						System.out.println("mySNSServer:    Nome do Ficheiro " + fileName);

						File f = new File(p+fileName);

						if (f.exists()) {

							System.out.println("mySNSServer:       Ficheiro " + fileName + " existe.");

							outStream.writeObject("True");
							outStream.writeObject(String.valueOf(f.length()));

							FileInputStream in = new FileInputStream(f);
							OutputStream out = socket.getOutputStream();

							sendFile(in, out);


						} else {
							System.out.println("mySNSServer:       Ficheiro " + fileName + " não existe.");
							outStream.flush();
							outStream.writeObject("False");
						}

						command = (String) inStream.readObject();
						System.out.println("mySNSServer:       Comando a seguir " + command);						

					}

					System.out.println("mySNSServer: Fim de receber todos os ficheiros");
				}
				else {
					//Send this to the client
					System.out.println("mySNSServer: Inválido ID/Password.");
				}


			} catch (IOException | ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

}
