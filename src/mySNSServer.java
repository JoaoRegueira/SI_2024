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
		//System.setProperty("javax.net.ssl.keyStore", "keystore.server");
		//System.setProperty("javax.net.ssl.keyStorePassword", "amora1337");
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
        //sSoc.close();
    }
	
	/*
	public void startServer() {
		//ServerSocket sSoc = null;
		ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();
		ServerSocket ss = null;

		try {
			ss = ssf.createServerSocket(23456);
		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		}

		while (true) {
			try {
				(new mySNSServer.ServerThread(ss.accept())).start();
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
	}
	*/

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

	public boolean CreateMACfile(String password, String useCase) throws NoSuchAlgorithmException, InvalidKeyException, IOException {

		File myObj = new File("password.mac");
		File userMyObj = new File("users.txt");
		//System.out.println(password);

		if (useCase.equals("createNew")) {
			if (myObj.createNewFile()) {
				System.out.println("   CreateMACfile: Criar intregridade dos dados de utilizadores.");    //Criar o MAC
				//gerar a chave a partir da password
				byte[] pass = "admin".getBytes();  // create Mac ---
				SecretKey key = new SecretKeySpec(pass, "AES");
				Mac m;
				byte[] mac = null;
				m = Mac.getInstance("HmacSHA256");
				m.init(key);
				m.update(File_To_Array(userMyObj));
				mac = m.doFinal();  // ---

				FileWriter myWriter = new FileWriter("password.mac");
				myWriter.write(Base64.getEncoder().encodeToString(mac)); //escreve mac em ficheiro
				//System.out.println("MAC ORIGINAL: "+Base64.getEncoder().encodeToString(mac));
				myWriter.close();
				System.out.println("   CreateMACfile: Ficheiro criado, " + myObj.getName());
				return true;


			} else {
				System.out.println("   CreateMACfile: Ficheiro MAC ja existe");
				return false;
			}
		} else if(useCase.equals("Update")){

			byte[] pass = "admin".getBytes();  // create Mac ---
			SecretKey key = new SecretKeySpec(pass, "AES");
			Mac m;
			byte[] mac = null;
			m = Mac.getInstance("HmacSHA256");
			m.init(key);
			m.update(File_To_Array(userMyObj));
			mac = m.doFinal();  // ---


			BufferedWriter writer = new BufferedWriter(new FileWriter("password.mac"));
			//System.out.println("Updating MAC with"+Base64.getEncoder().encodeToString(mac));
			writer.write(Base64.getEncoder().encodeToString(mac));
			writer.close();

			System.out.println("   CreateMACfile: Ficheiro atualizado, " + myObj.getName());

			return true;
		}

		return false;

	}

	public Boolean check_MAC(String password) throws IOException, NoSuchAlgorithmException, InvalidKeyException {

		File myObj = new File("password.mac");
		File userMyObj = new File("users.txt");

		byte [] pass = "admin".getBytes();  // create Mac ---
		SecretKey key = new SecretKeySpec(pass, "AES");
		Mac m;
		byte[]mac = null;
		m = Mac.getInstance("HmacSHA256");
		m.init(key);
		m.update(File_To_Array(userMyObj));
		mac = m.doFinal();  // ---

		String Mac_File = null;
		Scanner myReader = new Scanner(myObj); //reads mac file
		while (myReader.hasNextLine()) {
			Mac_File = myReader.nextLine();
		}
		myReader.close();

		if (Base64.getEncoder().encodeToString(mac).equals(Mac_File)){
			return true;
		}

		return false;
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

	public boolean interactWithUserTxt(String username, String password, String toDo) throws IOException, NoSuchAlgorithmException { //toDo = Create / checkUser / createNewUser

		File myObj = new File("users.txt");
		File UserFolder = new File(username);
		String filePath = "users.txt";

		//Transform pass to byte[]
		byte[] passwordS = HextoByte(password);

		if (toDo.equals("Create")){
			if (myObj.createNewFile()) { // verifica se consegue criar o ficheiro
				System.out.println("   interactWithUserTxt: Ficheiro de utilizadores, users.txt, criado.");
				return true;
			}else {
				System.out.println("   interactWithUserTxt: Ficheiro de utilizadores já existe no sistema.");
				return false;
			}
		} else if (toDo.equals("CheckUser")){
			//String stringToCompare = username+";"+password;

			try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
				String line = null;

				while ((line = reader.readLine()) != null) {
					if (line.split(";").length > 1) {
						String username_inFile = line.split(";")[0];
						String password_inFile = line.split(";")[1];

						// Compare the line to the string
						if (line.split(";")[0].equals(username)) {
							String line_salt = line.split(";")[2];

							//Encripts password
							MessageDigest passwordSint = MessageDigest.getInstance("SHA-256");
							passwordSint.update(HextoByte(line_salt));
							byte[] passHash_s = passwordSint.digest(passwordS);
							String passHash_str = BytetoHex(passHash_s);

							//check if RECEIVED salted password is the as FILE salted password
							if(line.split(";")[1].equals(passHash_str)){
								System.out.println("   interactWithUserTxt: Utilizador encontrado, " + line);
								return true;
							}
						
						}
					}
				}
				return false;
			} catch (IOException e) {
				e.printStackTrace();
			}
			// NEW STUFF: Verifica se o user já existe no TXT e Pasta do user criada
		} else if (toDo.equals("createNewUser")){

			try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
				String line = null;

				while ((line = reader.readLine()) != null) {
					String username_inFile = line.split(";")[0];

					// Compare the line to the string
					if (line.split(";")[0].equals(username)) {
						System.out.println("   interactWithUserTxt: Nome do utilizador já existe no ficheiro de utilizadores.");
						return false;
					} else {
						System.out.println("   interactWithUserTxt: Criando utilizador cujo nome é"+ username);
					}
				}
			} catch (IOException e) {
				e.printStackTrace();
			}

			//create salt
			SecureRandom random = new SecureRandom();
			byte[] salt = new byte[16];
			random.nextBytes(salt);
			String ssalt = BytetoHex(salt);

			//Encripts password
			MessageDigest passwordSint = MessageDigest.getInstance("SHA-256");
			passwordSint.update(salt);
			byte[] passHash_s = passwordSint.digest(passwordS);
			String passHash_str = BytetoHex(passHash_s);

			//user added to file
			String lineToAdd = username+";"+passHash_str+";"+ssalt+"\n"; //File format User;Pass_Salted;Salt

			try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath, true))) {
				// Append the line to the file
				writer.write(lineToAdd);
				writer.newLine();
				File userDir = new File("Servidor/"+username);

				if(userDir.mkdirs()){
					System.out.println("   interactWithUserTxt: Pasta do utilizador criado");
				} else {
					System.out.println("   interactWithUserTxt: Não foi possível criar pasta do utilizador");
					return false;
				}

				System.out.println("   interactWithUserTxt: Utilizador adicionado ao ficheiro de utilizaodres users.txt.");
				return true;
			} catch (IOException e) {
				e.printStackTrace();
				return false;
			}
		}
		System.out.println("Problem using the function");
		return false;
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
				//String passwd = (String)inStream.readObject();  //recebe password

				System.out.println(userCommand);
				System.out.println(userID); //Utente
				//System.out.println(passwd);

				if (userCommand.equals("-au")) {
					/*
					//Criação de utilizador
					if (interactWithUserTxt(userID, passwd, "createNewUser")) {

						System.out.println("mySNSServer: Utilizador adicionado ao ficheiro de utilizadores.");

						if (CreateMACfile(passwd, "createNew")) {

							System.out.println("mySNSServer:    Integridade dos dados de utilizadores criada.");
							
							String fileName = (String) inStream.readObject();
							System.out.println("mySNSServer: Nome do Ficheiro " + fileName);
							String fileSize = (String) inStream.readObject();
							System.out.println("mySNSServer:    tamanho, em bytes, do Ficheiro " + fileSize);

							InputStream in = socket.getInputStream();
							receiveFile(fileName, userID, in, Integer.valueOf(fileSize));

						} else {
							if (CreateMACfile(passwd, "Update")) {

								System.out.println("mySNSServer:    Integridade dos dados de utilizadores atualizada.");
								
								String fileName = (String) inStream.readObject();
								System.out.println("mySNSServer: Nome do Ficheiro " + fileName);
								String fileSize = (String) inStream.readObject();
								System.out.println("mySNSServer:    tamanho, em bytes, do Ficheiro " + fileSize);

								InputStream in = socket.getInputStream();
								receiveFile(fileName, userID, in, Integer.valueOf(fileSize));

							}
						}
					}
					*/
				} else if (userCommand.equals("-u") /*&& interactWithUserTxt(userID, passwd, "CheckUser")*/) {

					System.out.println("mySNSServer: Utilizador Reconhecido.");
					
					/*
					if (check_MAC(passwd)) {
						System.out.println("mySNSServer:    Integridade dos dados de utilizadores não comprometida");
					} else {
						System.out.println("mySNSServer:    Integridade dos dados de utilizadores comprometida");
						//socket.close();
					}
					*/

					System.out.println("mySNSServer: Inicio de receber todos os ficheiros.");

					String command = (String) inStream.readObject();

					while (command.equals("-sc")) {

						System.out.println("mySNSServer:    Comando -sc reconhecido");

						String fileName = (String) inStream.readObject();
						System.out.println("mySNSServer: Nome do Ficheiro " + fileName);
						String fileSize = (String) inStream.readObject();
						System.out.println("mySNSServer:    tamanho, em bytes, do Ficheiro " + fileSize);

						InputStream in = socket.getInputStream();
						receiveFile(fileName, userID, in, Integer.valueOf(fileSize));

						command = (String) inStream.readObject();

					}

					while (command.equals("-sa")) {

						System.out.println("mySNSServer:    Comando -sa reconhecido");

						String fileName = (String) inStream.readObject();
						System.out.println("mySNSServer: Nome do Ficheiro " + fileName);
						String fileSize = (String) inStream.readObject();
						System.out.println("mySNSServer:    tamanho, em bytes, do Ficheiro " + fileSize);

						InputStream in = socket.getInputStream();
						receiveFile(fileName, userID, in, Integer.valueOf(fileSize));

						command = (String) inStream.readObject();
						System.out.println("Next command is: "+command);

					}

					while (command.equals("-se")) {

						System.out.println("mySNSServer:    Comando -se reconhecido");

						String fileName = (String) inStream.readObject();
						System.out.println("mySNSServer: Nome do Ficheiro " + fileName);
						String fileSize = (String) inStream.readObject();
						System.out.println("mySNSServer:    tamanho, em bytes, do Ficheiro " + fileSize);

						InputStream in = socket.getInputStream();
						receiveFile(fileName, userID, in, Integer.valueOf(fileSize));

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
					
					command = (String) inStream.readObject();
					
					while (command.equals("-d")) {

						System.out.println("mySNSServer:    Comando -d reconhecido");

						String process = (String) inStream.readObject();
						String userDest = (String) inStream.readObject();

						while (process.equals("-c")) {

							System.out.println("mySNSServer:       Comando -c reconhecido");

							String fileName = (String) inStream.readObject();
							System.out.println("mySNSServer:          Nome do Ficheiro " + fileName);
							String fileSize = (String) inStream.readObject();
							System.out.println("mySNSServer:          tamanho, em bytes, do Ficheiro " + fileSize);

							InputStream in = socket.getInputStream();
							receiveFile(fileName, userDest, in, Integer.valueOf(fileSize));

							process = (String) inStream.readObject();

						}

						while (process.equals("-s")) {

							System.out.println("mySNSServer:    Comando -s reconhecido");

							String fileName = (String) inStream.readObject();
							System.out.println("mySNSServer:       Nome do Ficheiro " + fileName);
							String fileSize = (String) inStream.readObject();
							System.out.println("mySNSServer:       tamanho, em bytes, do Ficheiro " + fileSize);

							InputStream in = socket.getInputStream();
							receiveFile(fileName, userDest, in, Integer.valueOf(fileSize));

							process = (String) inStream.readObject();

						}

						while (process.equals("-e")) {

							System.out.println("mySNSServer:    Comando -e reconhecido");

							String fileName = (String) inStream.readObject();
							System.out.println("mySNSServer:    Nome do Ficheiro " + fileName);
							String fileSize = (String) inStream.readObject();
							System.out.println("mySNSServer:    tamanho, em bytes, do Ficheiro " + fileSize);

							InputStream in = socket.getInputStream();
							receiveFile(fileName, userDest, in, Integer.valueOf(fileSize));

							process = (String) inStream.readObject();

						}

						while (process.equals("-g")) {

							System.out.println("mySNSServer:    Comando -g reconhecido");
							String fileName = (String) inStream.readObject();

							System.out.println("mySNSServer:       Nome do Ficheiro " + fileName);

							String p = "Servidor/"+userDest+"/";

							File f = new File(p+fileName);

							if (f.exists()) {

								System.out.println("mySNSServer: Ficheiro " + fileName + " existe.");

								outStream.writeObject("True");
								outStream.writeObject(String.valueOf(f.length()));

								FileInputStream in = new FileInputStream(f);
								OutputStream out = socket.getOutputStream();

								sendFile(in, out);


							} else {
								System.out.println("mySNSServer: Ficheiro " + fileName + " não existe.");
								outStream.flush();
								outStream.writeObject("False");
							}

							process = (String) inStream.readObject();
							System.out.println("Next process is: "+process);

						}

						command = (String) inStream.readObject();
						System.out.println("Next command is: "+command);

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
