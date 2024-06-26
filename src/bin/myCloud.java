
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

public class myCloud {
	
	public static boolean ReadFileVerifySign (PublicKey pk, byte[] signature, byte[] dataSigned) {

		try {
			
			Signature s = Signature.getInstance("SHA256withRSA");
			s.initVerify(pk);
			s.update(dataSigned);
			
			if (s.verify(signature)) {
				System.out.println("Message is valid");
				return true;
			}
			else
				System.out.println("Message was corrupted");
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return false;
	}
	
	public static void decryptFile(String fileToDecrypt, SecretKey sk, String finalNameFile) {

		try {
			Cipher c = Cipher.getInstance("AES");
			byte[] keyEncoded = sk.getEncoded();
			SecretKeySpec keySpec2 = new SecretKeySpec(keyEncoded, "AES");
			c.init(Cipher.DECRYPT_MODE, keySpec2);

			FileInputStream fis;
			FileOutputStream fos;
			CipherOutputStream cos;

			fis = new FileInputStream(fileToDecrypt);
			fos = new FileOutputStream(finalNameFile);
			cos = new CipherOutputStream(fos, c);

			byte[] b = new byte[16];
			int i;

			while ((i=fis.read(b) )!= -1) {
				cos.write(b, 0, i);
			}

			cos.close();
			fis.close();

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
	public static SecretKey convertStringToSecretKeyto(String encodedKey) {
	    byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
	    SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
	    return originalKey;
	}
	
	public static byte[] readFileToBytes(String filePath, int l) throws IOException {

	      File file = new File(filePath);
	      byte[] bytes = new byte[l];

	      FileInputStream fis = null;
	      try {

	          fis = new FileInputStream(file);

	          //read file into bytes[]
	          fis.read(bytes);

	      } finally {
	          if (fis != null) {
	              fis.close();
	              return bytes;
	          }
	      }
		return bytes;

	  }
	
	public static byte[] decrypt(byte[] data, PrivateKey privateKey) {

		try {
			
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
	        byte[] sk = cipher.doFinal(data);
	        return sk;
	        
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        return null;
    }

	public static void cipherSecretKey(SecretKey key, PublicKey pk, File f) {

		System.out.println();
		System.out.println("   cipherSecretKey: Função Incializada.");

		// Initialize the cipher object
		Cipher cipher;
		try {
			// Create a cipher object with the "RSA" algorithm
			cipher = Cipher.getInstance("RSA");
			// Initialize the cipher object in encryption mode with the given public key
			cipher.init(Cipher.ENCRYPT_MODE, pk);

			// Encrypt the secret key by calling the doFinal method of the cipher object
			byte[] bytes = cipher.doFinal(key.getEncoded());

			// Save the encrypted key to a file with the same name as the input file and ".chave_secreta" extension
			OutputStream os = new FileOutputStream(f.getName() + ".chave_secreta");
			os.write(bytes);
			os.close();

		} catch (NoSuchAlgorithmException e) {
			// Handle the NoSuchAlgorithmException that may be thrown by the getInstance method of the Cipher class
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// Handle the NoSuchPaddingException that may be thrown by the getInstance method of the Cipher class
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// Handle the InvalidKeyException that may be thrown by the init method of the Cipher class
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// Handle the IllegalBlockSizeException that may be thrown by the doFinal method of the Cipher class
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// Handle the BadPaddingException that may be thrown by the doFinal method of the Cipher class
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// Handle the FileNotFoundException that may be thrown by the FileOutputStream constructor
			e.printStackTrace();
		} catch (IOException e) {
			// Handle the IOException that may be thrown by the write and close methods of the OutputStream class
			e.printStackTrace();
		}

		System.out.println("   cipherSecretKey: Função terminada.");
	}
	
	public static void cipherFile(SecretKey key, File f) {

		System.out.println();
		System.out.println("   cipherFile: Função Incializada.");

		Cipher c;

		try {

			// Get an instance of the AES cipher and initialize it with the given secret key for encryption
			c = Cipher.getInstance("AES");
			c.init(Cipher.ENCRYPT_MODE, key);

			FileInputStream fis;
			FileOutputStream fos;
			CipherOutputStream cos;

			// Read the input file
			fis = new FileInputStream(f);
			// Create an output file with a .cifrado extension
			fos = new FileOutputStream(f.getName() + ".cifrado");

			// Create a CipherOutputStream that will write the encrypted data to the output file
			cos = new CipherOutputStream(fos, c);

			byte[] b = new byte[16];
			int i = fis.read(b);

			// Encrypt the input file and write the encrypted data to the output file
			while (i != -1) {
				cos.write(b, 0, i);
				i = fis.read(b);
			}

			// Close the streams
			cos.close();
			fis.close();

			System.out.println("   cipherFile: Função terminada.");

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		System.out.println("   cipherFile: Função terminada.");

	}

	public static SecretKey secretKeyMaker() {

		System.out.println();
		System.out.println("   secretKeyMaker: Função Incializada.");

		KeyGenerator kg; // Initialize the key generator object.
		try {
			// Get the instance of AES key generator.
			kg = KeyGenerator.getInstance("AES");
			// Initialize the key generator with a 128-bit key size.
			kg.init(128);
			// Generate a new AES secret key.
			SecretKey key = kg.generateKey();

			System.out.println("   secretKeyMaker: Fim");

			return key;

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		System.out.println("   secretKeyMaker: Função terminada");
		return null;
	}

	public static void criaAssinatura(String file, PrivateKey pk) {

		// Print message indicating that the method has started
		System.out.println();
		System.out.println("   criaAssinatura: Função inicializada.");
		try {
			// Read the input file into a byte array
			File f = new File(file);
			byte[] fileBuf = File_To_Array(f);

			// Initialize a Signature object with the "SHA256withRSA" algorithm and the provided private key
			Signature s = Signature.getInstance("SHA256withRSA");
			s.initSign(pk);

			// Update the signature object with the contents of the input file
			s.update(fileBuf);

			// Generate the signature bytes and write them to a separate file with the ".assinatura" extension
			byte[] signature = s.sign();
			try (FileOutputStream fos = new FileOutputStream(file + ".assinatura")) {
				fos.write(signature);
			}

			// Write the original file to a separate file with the ".assinado" extension
			try (FileOutputStream fos = new FileOutputStream(file + ".assinado")) {
				fos.write(fileBuf);
			}

			// Print message indicating that the signature and signed file have been successfully created
			System.out.println("   criaAssinatura: Assinatura criada em: " + file + ".assinado");
			System.out.println("   criaAssinatura: Assinatura criada em: " + file + ".assinatura");

			// Catch and handle exceptions that may occur during the signing process
		} catch (NoSuchAlgorithmException e) {
			System.err.println("     Erro: Algoritmo de assinatura inválido.");
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			System.err.println("     Erro: Arquivo não encontrado.");
			e.printStackTrace();
		} catch (IOException e) {
			System.err.println("     Erro: Falha ao ler/escrever arquivo.");
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			System.err.println("     Erro: Chave inválida.");
			e.printStackTrace();
		} catch (SignatureException e) {
			System.err.println("     Erro: Falha ao assinar o arquivo.");
			e.printStackTrace();
		}

		// Print message indicating that the method has finished
		System.out.println("   criaAssinatura: Função Terminada.");
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

	// To convert file to byte array
	public static byte[] File_To_Array(File file) throws IOException {

		// Creating an object of FileInputStream to
		// read from a file
		FileInputStream fl = new FileInputStream(file);

		// Now creating byte array of same length as file
		byte[] arr = new byte[(int) file.length()];

		// Reading file content to byte array
		// using standard read() method
		fl.read(arr);

		// lastly closing an instance of file input stream
		// to avoid memory leakage
		fl.close();

		// Returning above byte array
		return arr;
	}

	public static void sendFile (InputStream in, OutputStream out) {
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
	}

	public static void receiveFile(String fileName, InputStream in, int fileSize) {

		System.out.println();
		System.out.println("   receiveFile: Função inicializada");

		OutputStream out = null;
		byte[] bytes = new byte[1024];

		try {
			out = new FileOutputStream(fileName);
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
	
	public static String BytetoHex(byte[] arrayB) {

        String HexString = "";
        for (byte b : arrayB) {
            String st = String.format("%02X", b);
            HexString += st;
        }

        return HexString;
    }
	
	public static void commandC(String fileName, String format, ObjectOutputStream oS, Socket socket, SecretKey sk, PublicKey publicKey) {

		try {

			File f = new File(fileName);

			if (f.exists()) {

				cipherFile(sk, f);
				cipherSecretKey(sk, publicKey, f);
				String cipherFileName;
				String secretFileFileName;
				
				if (!format.equals("")) {
					cipherFileName = fileName+".cifrado."+format;
					secretFileFileName = fileName+".chave_secreta."+format;
					
				} else {
					cipherFileName = fileName+".cifrado";
					secretFileFileName = fileName+".chave_secreta";
				}

				//Enviar ficheiro cifrado
				f = new File(fileName+".cifrado");

				oS.writeObject(cipherFileName);
				oS.writeObject(String.valueOf(f.length()));

				InputStream in = new FileInputStream(f);
				OutputStream out = socket.getOutputStream();

				sendFile(in, out);
				//Ficheiro cifrado enviado

				//Enviar chave secreta
				oS.writeObject("-c");

				f = new File(fileName+".chave_secreta");

				oS.writeObject(secretFileFileName);
				oS.writeObject(String.valueOf(f.length()));

				in = new FileInputStream(f);

				sendFile(in, out);
				//Chave secreta enviada

				System.out.println("MyCloud: Enviado ficheiro cifrado, chave secreta");

			} else {
				System.out.println("MyCloud: Ficheiro não existe");
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


	}

	public static void commandS(String fileName, String format, ObjectOutputStream oS, Socket socket , PrivateKey privateKey) {
		
		String sigantureFileName;
		String signedFileFileName;
		
		if (!format.equals("")) {
			sigantureFileName = fileName+".assinatura."+format;
			signedFileFileName = fileName+".assinado."+format;
			
		} else {
			sigantureFileName = fileName+".assinatura";
			signedFileFileName = fileName+".assinado";
		}
		
		File f = new File(fileName);

		if (f.exists()) {


			try {
				criaAssinatura(fileName, privateKey);

				//Enviar ficheiro assinado
				f = new File(fileName+".assinado");
				oS.writeObject(signedFileFileName);
				oS.writeObject(String.valueOf(f.length()));

				InputStream in = new FileInputStream(f);
				OutputStream out = socket.getOutputStream();

				sendFile(in, out);
				//Ficheiro assinado enviado


				//Enviar assinatura
				oS.writeObject("-s");

				f = new File(fileName+".assinatura");

				oS.writeObject(sigantureFileName);
				oS.writeObject(String.valueOf(f.length()));

				in = new FileInputStream(f);

				sendFile(in, out);
				//Assinatura enviada

				System.out.println("MyCloud: Enviado ficheiro assinado e assinatura");

			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}


		} else {

			System.out.println("MyCloud: Ficheiro não existe");

		}
	}

	public static void commandE(String fileName, ObjectOutputStream oS, Socket socket, PrivateKey privateKey, SecretKey sk, PublicKey publicKey) {
		File f = new File(fileName);

		if (f.exists()) {

			criaAssinatura(fileName, privateKey);
			f = new File(fileName+".assinado");
			cipherFile(sk, f);
			cipherSecretKey(sk, publicKey, f);
			
			try {
				Files.deleteIfExists(Paths.get(fileName+".assinado"));
				//Enviar ficheiro assinado/cifrado
				f = new File(fileName+".assinado.cifrado");

				oS.writeObject(f.getName());
				oS.writeObject(String.valueOf(f.length()));

				InputStream in = new FileInputStream(f);
				OutputStream out = socket.getOutputStream();

				sendFile(in, out);
				//Ficheiro assinado/cifrado enviado


				//Enviar assinatura
				oS.writeObject("-e");

				f = new File(fileName+".assinatura");

				oS.writeObject(f.getName());
				oS.writeObject(String.valueOf(f.length()));

				in = new FileInputStream(f);

				sendFile(in, out);
				//Assinatura enviada


				//Enviar chave secreta
				oS.writeObject("-e");

				f = new File(fileName+".assinado.chave_secreta");

				oS.writeObject(f.getName());
				oS.writeObject(String.valueOf(f.length()));

				in = new FileInputStream(f);

				sendFile(in, out);
				//Chave secreta enviada

				System.out.println("MyCloud: Enviado ficheiro assinado/cifrado, chave secreta e assinatura");
				
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		} else {

			System.out.println("MyCloud: Ficheiro não existe");

		}
	}

	public static void main(String[] args) throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		System.setProperty("javax.net.ssl.trustStore", "truststore.client");
		System.setProperty("javax.net.ssl.trustStorePassword", "amora1337");
		SocketFactory sf = SSLSocketFactory.getDefault();

		if (args.length < 2) return;

		String hostname = null;
		int port = 0;
		
		String medico = "";
		String utente = "";

		if (args[0].equals("-a")) {
			
			//Extrair IP e Porto do Servidor
			String[] address = args[1].split(":");
			hostname = address[0];
			port = Integer.parseInt(address[1]);
			
			String userCommand = args[4];

			try {
				
				if (args[2].equals("-m")) {
					medico = args[3];
				}
				
				if (args[4].equals("-u")) {
					utente = args[5];
				}
				
				if (userCommand.equals("-au")) {
					/*
					//Extrair nomes de utilizador, password e certificado
					String username = args[3];
					String password = args[4];
					String certName = args[5];

					//Socket socket = new sf.createSocket(hostname, port);
					Socket socket = sf.createSocket(hostname, port);

					//Socket socket = new Socket(hostname, port);
					ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
					ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());
					
					
					byte[] passwordSint = MessageDigest.getInstance("SHA-256").digest(password.getBytes()); //Encripts user password
					String passHash = BytetoHex(passwordSint);
					
					
					//Envia User e password do cliente
					outStream.writeObject(userCommand);
					outStream.writeObject(username);
					outStream.writeObject(passHash);
					
					//Enviar certificado
					File f = new File(username+".cer");

					outStream.writeObject(f.getName());
					outStream.writeObject(String.valueOf(f.length()));

					InputStream in = new FileInputStream(f);
					OutputStream out = socket.getOutputStream();

					sendFile(in, out);
					//certificado enviado
					
					socket.close();
					*/
					
				} else if (userCommand.equals("-u")) {
					
					/*
					//extrair nome de utilizador, password e comando
					String username = args[3];
					String password = args[5];
					String command = args[6];
					
					System.out.println(username);
					System.out.println(password);
					System.out.println(command);
					*/
					
					//File RSAKeyStore = new File("keystore.SI030Cloud");
					//KeyPair kp = createRSAkey();
					SecretKey sk = secretKeyMaker();
					
					//keystore
					InputStream inputStream = new FileInputStream("keystore.userCloud");
					KeyStore kstore = KeyStore.getInstance("PKCS12");
					kstore.load(inputStream, "admin123".toCharArray());

					//Chave Privada
					PrivateKey privateKey = (PrivateKey) kstore.getKey(medico, "admin123".toCharArray());
					//System.out.println(privateKey);

					//Chave Publica
					Certificate cert = (Certificate) kstore.getCertificate(medico);
					PublicKey publicKey = cert.getPublicKey();
					//System.out.println(publicKey);
					
					//Socket socket = new Socket(hostname, port);
					Socket socket = sf.createSocket(hostname, port);
					ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
					ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());

					/*
					byte[] passwordSint = MessageDigest.getInstance("SHA-256").digest(password.getBytes()); //Encripts user password
					String passHash = BytetoHex(passwordSint);
					
					
					//Envia User e password do cliente
					outStream.writeObject(userCommand);
					outStream.writeObject(username);
					outStream.writeObject(passHash);
					*/
					
					String command = args[6];
					
					outStream.writeObject(userCommand);
					outStream.writeObject(utente);
					
					if ( /* userCommand.equals("-u") && */ command.equals("-sc")) {

						System.out.println("MyCloud: Comando -sc reconhecido");

						for (int i = 7; i < args.length; i++) {

							outStream.writeObject("-sc");

							File f = new File(args[i]);

							if (f.exists()) {

								cipherFile(sk, f);
								cipherSecretKey(sk, publicKey, f);

								//Enviar ficheiro cifrado
								f = new File(args[i]+".cifrado");

								outStream.writeObject(f.getName());
								outStream.writeObject(String.valueOf(f.length()));

								InputStream in = new FileInputStream(f);
								OutputStream out = socket.getOutputStream();

								sendFile(in, out);
								//Ficheiro cifrado enviado

								//Enviar chave secreta
								outStream.writeObject("-sc");

								f = new File(args[i]+".chave_secreta");

								outStream.writeObject(f.getName());
								outStream.writeObject(String.valueOf(f.length()));

								in = new FileInputStream(f);

								sendFile(in, out);
								//Chave secreta enviada

								System.out.println("MyCloud: Enviado ficheiro cifrado, chave secreta");
								
								//outStream.writeObject("Over and out");

							} else {
								System.out.println("MyCloud: Ficheiro não existe");
							}
						} 

						outStream.writeObject("Done");
						socket.close();

					} else if (/* userCommand.equals("-u") && */ command.equals("-sa")) {

						System.out.println("MyCloud: Comando -sa reconhecido");

						for (int i = 7; i < args.length; i++) {

							outStream.writeObject("-sa");

							File f = new File(args[i]);

							if (f.exists()) {

								criaAssinatura(args[i], privateKey);


								//Enviar ficheiro assinado
								f = new File(args[i]+".assinado");

								outStream.writeObject(f.getName());
								outStream.writeObject(String.valueOf(f.length()));

								InputStream in = new FileInputStream(f);
								OutputStream out = socket.getOutputStream();

								sendFile(in, out);
								//Ficheiro assinado enviado


								//Enviar assinatura
								outStream.writeObject("-sa");

								f = new File(args[i]+".assinatura");

								outStream.writeObject(f.getName());
								outStream.writeObject(String.valueOf(f.length()));

								in = new FileInputStream(f);

								sendFile(in, out);
								//Assinatura enviada

								System.out.println("MyCloud: Enviado ficheiro assinado e assinatura");
								
								//outStream.writeObject("Over and out");

							} else {

								System.out.println("MyCloud: Ficheiro não existe");

							}
						} 

						outStream.writeObject("Done");
						socket.close();

					} else if (/*userCommand.equals("-u") &&*/ command.equals("-se")) {

						System.out.println("MyCloud: Comando -se reconhecido.");

						for (int i = 7; i < args.length; i++) {

							outStream.writeObject("-se");

							File f = new File(args[i]);

							if (f.exists()) {

								criaAssinatura(args[i], privateKey);
								f = new File(args[i]+".assinado");
								cipherFile(sk, f);
								cipherSecretKey(sk, publicKey, f);
								Files.deleteIfExists(Paths.get(args[i]+".assinado"));


								//Enviar ficheiro assinado/cifrado
								f = new File(args[i]+".assinado.cifrado");

								outStream.writeObject(f.getName());
								outStream.writeObject(String.valueOf(f.length()));

								InputStream in = new FileInputStream(f);
								OutputStream out = socket.getOutputStream();

								sendFile(in, out);
								//Ficheiro assinado/cifrado enviado


								//Enviar assinatura
								outStream.writeObject("-se");

								f = new File(args[i]+".assinatura");

								outStream.writeObject(f.getName());
								outStream.writeObject(String.valueOf(f.length()));

								in = new FileInputStream(f);

								sendFile(in, out);
								//Assinatura enviada


								//Enviar chave secreta
								outStream.writeObject("-se");

								f = new File(args[i]+".assinado.chave_secreta");

								outStream.writeObject(f.getName());
								outStream.writeObject(String.valueOf(f.length()));

								in = new FileInputStream(f);

								sendFile(in, out);
								//Chave secreta enviada

								System.out.println("MyCloud: Enviado ficheiro assinado/cifrado, chave secreta e assinatura");
								
								outStream.writeObject("Over and out");

							} else {

								System.out.println("MyCloud: Ficheiro não existe");

							}
						} 

						outStream.writeObject("Done");
						socket.close();

					} else if (/* userCommand.equals("-u") && */ command.equals("-g")) {

						System.out.println("MyCloud: Comando -g reconhecido.");

						InputStream in = socket.getInputStream();
						
						boolean askJoaoCert = false;

						for (int i = 7; i < args.length; i++) {
							
							askJoaoCert = false;

							try {

								outStream.writeObject("-g");
								outStream.writeObject(args[i]+".assinado.cifrado");

								if ((inStream.readObject()).equals("True")) {

									String s = (String) inStream.readObject();
									System.out.println("MyCloud: Tamanho do ficheiro " + args[i]+".assinado.cifrado" + " de " + s + " bytes");

									receiveFile(args[i]+".assinado.cifrado", in, Integer.valueOf(s));

									outStream.writeObject("-g");
									outStream.writeObject(args[i]+".assinado.chave_secreta");

									inStream.readObject();

									s = (String) inStream.readObject();
									System.out.println("MyCloud: Tamanho do ficheiro " + args[i]+".assinado.chave_secreta" + " de " + s + " bytes");

									receiveFile(args[i]+".assinado.chave_secreta", in, Integer.valueOf(s));

									outStream.writeObject("-g");
									outStream.writeObject(args[i]+".assinatura");

									inStream.readObject();

									s = (String) inStream.readObject();
									System.out.println("MyCloud: Tamanho do ficheiro " + args[i]+".assinatura" + " de " + s + " bytes");

									receiveFile(args[i]+".assinado.chave_secreta", in, Integer.valueOf(s));
									

								} else {
									
									System.out.println();
									System.out.println("MyCloud: Ficheiro " + args[i]+".assinado.cifrado não existe no servidor MyCloudServer.");
									System.out.println();
									
								}
								
								outStream.writeObject("-g");
								outStream.writeObject(args[i]+".cifrado");

								if ((inStream.readObject()).equals("True")) {

									String s = (String) inStream.readObject();
									System.out.println("MyCloud: ficheiro " + args[i]+".cifrado" + " existe no servidor.");
									System.out.println("MyCloud: Tamanho do ficheiro " + args[i]+".cifrado" + " de " + s + " bytes.");

									receiveFile(args[i]+".cifrado", in, Integer.valueOf(s));

									outStream.writeObject("-g");
									outStream.writeObject(args[i]+".chave_secreta");

									inStream.readObject();

									s = (String) inStream.readObject();
									System.out.println("MyCloud: Tamanho do ficheiro " + args[i]+".chave_secreta" + " de " + s + " bytes");

									receiveFile(args[i]+".chave_secreta", in, Integer.valueOf(s));
									
									//Decifra chave secreta
									byte[] rcvSecretKey = decrypt(readFileToBytes(args[i]+".chave_secreta", Integer.valueOf(s)), privateKey);
									//System.out.println(secretKeySTR);
									
									SecretKey originalKey = new SecretKeySpec(rcvSecretKey, 0, rcvSecretKey.length, "AES");
									
									decryptFile(args[i]+".cifrado", originalKey, args[i]);


								} else {
									
									System.out.println();
									System.out.println("MyCloud: Ficheiro " + args[i]+".cifrado não existe no servidor MyCloudServer.");
									System.out.println();
									
								}
							
								outStream.writeObject("-g");
								outStream.writeObject(args[i]+".assinado");
								
								if ((inStream.readObject()).equals("True")) {

									String s = (String) inStream.readObject();
									System.out.println("MyCloud: " + args[i]+".assinado existe no servidor");
									System.out.println("MyCloud: Tamanho do ficheiro " + args[i]+".assinado" + " de " + s + " bytes");

									receiveFile(args[i]+".assinado", in, Integer.valueOf(s));

									outStream.writeObject("-g");
									outStream.writeObject(args[i]+".assinatura");

									inStream.readObject();

									s = (String) inStream.readObject();
									System.out.println("MyCloud: Tamanho do ficheiro " + args[i]+".assinatura" + " de " + s + " bytes");

									receiveFile(args[i]+".assinatura", in, Integer.valueOf(s));
									
									File assinatura = new File(args[i]+".assinatura");
									File assinado = new File(args[i]+".assinado");
									
									ReadFileVerifySign(publicKey, File_To_Array(assinatura), File_To_Array(assinado));
									

								} else {
									
									System.out.println();
									System.out.println("MyCloud: Ficheiro " + args[i]+".assinado não existe no servidor MyCloudServer.");
									System.out.println();
									
								}
								/*
								outStream.writeObject("-g");
								outStream.writeObject(args[i]+".cifrado.joao");
								
								if ((inStream.readObject()).equals("True")) {

									String s = (String) inStream.readObject();
									System.out.println("MyCloud: ficheiro " + args[i]+".cifrado.joao" + " existe no servidor.");
									System.out.println("MyCloud: Tamanho do ficheiro " + args[i]+".cifrado.joao" + " de " + s + " bytes.");

									receiveFile(args[i]+".cifrado.joao", in, Integer.valueOf(s));

									outStream.writeObject("-g");
									outStream.writeObject(args[i]+".chave_secreta.joao");

									inStream.readObject();

									s = (String) inStream.readObject();
									System.out.println("MyCloud: Tamanho do ficheiro " + args[i]+".chave_secreta.joao" + " de " + s + " bytes");

									receiveFile(args[i]+".chave_secreta.joao", in, Integer.valueOf(s));

									//Decifra chave secreta
									byte[] rcvSecretKey = decrypt(readFileToBytes(args[i]+".chave_secreta.joao", Integer.valueOf(s)), privateKey);
									//System.out.println(secretKeySTR);

									SecretKey originalKey = new SecretKeySpec(rcvSecretKey, 0, rcvSecretKey.length, "AES");

									decryptFile(args[i]+".cifrado.joao", originalKey, args[i]);


								} else {

									System.out.println();
									System.out.println("MyCloud: Ficheiro " + args[i]+".cifrado.joao não existe no servidor MyCloudServer.");
									System.out.println();

								}
								
								
								outStream.writeObject("-g");
								outStream.writeObject(args[i]+".assinado.joao");

								if ((inStream.readObject()).equals("True")) {
									
									askJoaoCert = true;

									String s = (String) inStream.readObject();
									System.out.println("MyCloud: " + args[i]+".assinado.joao existe no servidor");
									System.out.println("MyCloud: Tamanho do ficheiro " + args[i]+".assinado.joao" + " de " + s + " bytes");

									receiveFile(args[i]+".assinado.joao", in, Integer.valueOf(s));

									outStream.writeObject("-g");
									outStream.writeObject(args[i]+".assinatura.joao");

									inStream.readObject();

									s = (String) inStream.readObject();
									System.out.println("MyCloud: Tamanho do ficheiro " + args[i]+".assinatura.joao" + " de " + s + " bytes");

									receiveFile(args[i]+".assinatura.joao", in, Integer.valueOf(s));
									
								} else {

									System.out.println();
									System.out.println("MyCloud: Ficheiro " + args[i]+".assinado.joao não existe no servidor MyCloudServer.");
									System.out.println();
									askJoaoCert =false;

								}*/
								
							} catch (ClassNotFoundException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							} catch (Exception e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
							

						} 
						/*
						if (askJoaoCert) {
							
							for (int i = 7; i < args.length; i++) {
								
								File assinatura = new File(args[i]+".assinatura.joao");
								File assinado = new File(args[i]+".assinado.joao");
								
								outStream.writeObject("Over and out");
								outStream.writeObject("-d");
								outStream.writeObject("-g");
								outStream.writeObject("joao");
								outStream.writeObject("joao.cer");
								
								inStream.readObject();
								
								String s = (String) inStream.readObject();
								System.out.println("MyCloud: Tamanho do ficheiro " + "joao.cert" + " de " + s + " bytes");
								
								receiveFile("joao.cer", in, Integer.valueOf(s));
								
								FileInputStream fis = new FileInputStream("joao.cer");
								CertificateFactory cf = CertificateFactory.getInstance("X.509");
								Certificate otherUserCert = cf.generateCertificate(fis);

								ReadFileVerifySign(otherUserCert.getPublicKey(), File_To_Array(assinatura), File_To_Array(assinado));
							}
							
						}
						*/
						
						outStream.writeObject("Over and out");
						outStream.writeObject("Done");
						socket.close();

					} else if (userCommand.equals("-u") && command.equals("-d")) {
						
						System.out.println("MyCloud: Comando -d reconhecido.");

						String userDest = args[7];
						String process = args[8];
						
						outStream.writeObject("-d");

						for (int i = 9; i < args.length; i++) {

							System.out.println("File to send: " + args[i]);

							if (process.equals("-c")) {
								
								System.out.println("MyCloud:    Comando -c reconhecido");

								
								outStream.writeObject("-d");
								outStream.writeObject("-g");
								outStream.writeObject(userDest);
								String fn = userDest+".cer";
								outStream.writeObject(fn);
								
								System.out.println("MyCloud:    Esperando por resposta do servidor");
								
								if ((inStream.readObject()).equals("True")) {

									String s = (String) inStream.readObject();
									System.out.println("MyCloud: Tamanho do ficheiro " + userDest+".cert" + " de " + s + " bytes");
									
									InputStream in = socket.getInputStream();
									
									receiveFile(userDest+".cer", in, Integer.valueOf(s));

								} else {

									System.out.println();
									System.out.println("MyCloud: Ficheiro " + userDest+".cer não existe no servidor MyCloudServer.");
									System.out.println();

								}
								
								FileInputStream fis = new FileInputStream(userDest+".cer");
								CertificateFactory cf = CertificateFactory.getInstance("X.509");
								Certificate otherUserCert = cf.generateCertificate(fis);
								
								outStream.writeObject("Over and out");
								outStream.writeObject("-d");
								outStream.writeObject("-c");
								outStream.writeObject(userDest);
								
								//commandC(args[i], username, outStream, socket, sk, otherUserCert.getPublicKey());
								outStream.writeObject("Over and out.");

							} else if (process.equals("-s")) {

								outStream.writeObject("-d");
								outStream.writeObject("-s");
								outStream.writeObject(userDest);
								//commandS(args[i], username, outStream, socket, privateKey);
								outStream.writeObject("Over and out.");

							} else if (process.equals("-e")) {
								
								outStream.writeObject("-d");
								outStream.writeObject("-s");
								outStream.writeObject(userDest);
								commandE(args[i], outStream, socket, privateKey, sk, publicKey);
								outStream.writeObject("Over and out.");
								
							}

						} 

						outStream.writeObject("Done");
						socket.close();

					
					} else {

						System.out.println("MyCloud: Comando " + command + " não reconhecido.");

						socket.close();
					}
					
				} else {
					System.out.println("MyCloud: Comando " + /* command + */ " não reconhecido.");
				}

			} catch (UnknownHostException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NumberFormatException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
}
