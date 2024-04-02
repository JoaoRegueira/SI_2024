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

public class mySNS {

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

	public static void main(String[] args) throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {

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
				} else {
					System.out.println("mySNS: Comando -m não detetado");
					return;
				}

				if (args[4].equals("-u")) {
					utente = args[5];
				} else {
					System.out.println("mySNS: Comando -u não detetado");
					return;
				}

				if (userCommand.equals("-u")) {


					SecretKey sk = secretKeyMaker();

					//keystore
					InputStream inputStream = new FileInputStream("keystore.userCloud");
					KeyStore kstore = KeyStore.getInstance("PKCS12");
					kstore.load(inputStream, "admin123".toCharArray());

					//Chave Privada
					PrivateKey privateKey = (PrivateKey) kstore.getKey(medico, "admin123".toCharArray());

					//Chave Publica
					Certificate cert = (Certificate) kstore.getCertificate(medico);
					PublicKey publicKey = cert.getPublicKey();
					//System.out.println(publicKey);

					Socket socket = new Socket(hostname, port);
					ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
					ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());

					String command = args[6];

					outStream.writeObject(userCommand);
					outStream.writeObject(utente);
					outStream.writeObject(medico);


					if (command.equals("-sc")) {

						System.out.println("mySNS: Comando -sc reconhecido");

						for (int i = 7; i < args.length; i++) {

							outStream.writeObject("-sc");

							File f = new File(args[i]);

							if (f.exists()) {

								cipherFile(sk, f);
								cipherSecretKey(sk, publicKey, f);

								//Enviar ficheiro cifrado
								f = new File(args[i]+".cifrado");
								File renomear = new File(args[i]+".chave_secreta."+utente);

								outStream.writeObject(f.getName());
								outStream.writeObject(String.valueOf(f.length()));

								if ((inStream.readObject()).equals("False")) {

									System.out.println("mySNS: Ficheiro cifrado e chave secreta existente no servidor");

								} else {

									InputStream in = new FileInputStream(f);
									OutputStream out = socket.getOutputStream();

									sendFile(in, out);
									//Ficheiro cifrado enviado

									//Enviar chave secreta
									outStream.writeObject("-sc");

									f = new File(args[i]+".chave_secreta");
									f.renameTo(renomear);

									outStream.writeObject(renomear.getName());
									outStream.writeObject(String.valueOf(renomear.length()));

									in = new FileInputStream(renomear);

									sendFile(in, out);
									//Chave secreta enviada

									System.out.println("mySNS: Enviado ficheiro cifrado, chave secreta");

								}

							} else {
								System.out.println("mySNS: Ficheiro não existe");
							}
						} 

						outStream.writeObject("Done");
						socket.close();

					} else if (command.equals("-sa")) {

						System.out.println("mySNS: Comando -sa reconhecido");

						for (int i = 7; i < args.length; i++) {

							outStream.writeObject("-sa");

							File f = new File(args[i]);
							File renomear = new File(args[i]+".assinatura."+medico);

							if (f.exists()) {

								criaAssinatura(args[i], privateKey);

								f = new File(args[i]+".assinado");

								outStream.writeObject(f.getName());
								outStream.writeObject(String.valueOf(f.length()));

								if ((inStream.readObject()).equals("False")) {

									System.out.println("mySNS: Ficheiro cifrado e chave secreta existente no servidor");

								} else {

									//Enviar ficheiro assinado
									InputStream in = new FileInputStream(f);
									OutputStream out = socket.getOutputStream();

									sendFile(in, out);
									//Ficheiro assinado enviado


									//Enviar assinatura
									outStream.writeObject("-sa");

									f = new File(args[i]+".assinatura");
									f.renameTo(renomear);

									outStream.writeObject(renomear.getName());
									outStream.writeObject(String.valueOf(renomear.length()));

									in = new FileInputStream(renomear);

									sendFile(in, out);
									//Assinatura enviada

									System.out.println("mySNS: Enviado ficheiro assinado e assinatura");
								}

							} else {

								System.out.println("mySNS: Ficheiro não existe");

							}
						} 

						outStream.writeObject("Done");
						socket.close();

					} else if (command.equals("-se")) {

						System.out.println("mySNS: Comando -se reconhecido.");

						for (int i = 7; i < args.length; i++) {

							outStream.writeObject("-se");

							File f = new File(args[i]);
							File renomearSeguro = new File(args[i]+".seguro");
							File renomearAssinatura = new File(args[i]+".seguro.assinatura");
							File renomearChaveSecreta = new File(args[i]+".seguro.chave_secreta");

							if (f.exists()) {

								criaAssinatura(args[i], privateKey);
								f = new File(args[i]+".assinado");
								cipherFile(sk, f);
								cipherSecretKey(sk, publicKey, f);
								Files.deleteIfExists(Paths.get(args[i]+".assinado"));



								f = new File(args[i]+".assinado.cifrado");
								f.renameTo(renomearSeguro);

								outStream.writeObject(renomearSeguro.getName());
								outStream.writeObject(String.valueOf(renomearSeguro.length()));

								if ((inStream.readObject()).equals("False")) {

									System.out.println("mySNS: Ficheiro cifrado e chave secreta existente no servidor");

								} else {

									//Enviar ficheiro assinado/cifrado
									InputStream in = new FileInputStream(renomearSeguro);
									OutputStream out = socket.getOutputStream();

									sendFile(in, out);
									//Ficheiro assinado/cifrado enviado

									//Enviar assinatura
									outStream.writeObject("-se");

									f = new File(args[i]+".assinatura");
									f.renameTo(renomearAssinatura);

									outStream.writeObject(renomearAssinatura.getName());
									outStream.writeObject(String.valueOf(renomearAssinatura.length()));

									in = new FileInputStream(renomearAssinatura);

									sendFile(in, out);
									//Assinatura enviada

									//Enviar chave secreta
									outStream.writeObject("-se");

									f = new File(args[i]+".assinado.chave_secreta");
									f.renameTo(renomearChaveSecreta);

									outStream.writeObject(renomearChaveSecreta.getName());
									outStream.writeObject(String.valueOf(renomearChaveSecreta.length()));

									in = new FileInputStream(renomearChaveSecreta);

									sendFile(in, out);
									//Chave secreta enviada


									System.out.println("mySNS: Enviado ficheiro assinado/cifrado, chave secreta e assinatura");

								}



							} else {

								System.out.println("mySNS: Ficheiro não existe");

							}
						} 

						outStream.writeObject("Done");
						socket.close();

					} else if (command.equals("-g")) {

						System.out.println("mySNS: Comando -g reconhecido.");

						InputStream in = socket.getInputStream();

						boolean askJoaoCert = false;

						for (int i = 7; i < args.length; i++) {

							//askJoaoCert = false;

							try {

								outStream.writeObject("-g");
								outStream.writeObject(args[i]+".seguro");

								if ((inStream.readObject()).equals("True")) {

									String s = (String) inStream.readObject();
									System.out.println("mySNS: Tamanho do ficheiro " + args[i]+".seguro" + " de " + s + " bytes");

									receiveFile(args[i]+".seguro", in, Integer.valueOf(s));

									outStream.writeObject("-g");
									outStream.writeObject(args[i]+".seguro.chave_secreta");

									inStream.readObject();

									s = (String) inStream.readObject();
									System.out.println("mySNS: Tamanho do ficheiro " + args[i]+".seguro.chave_secreta" + " de " + s + " bytes");

									receiveFile(args[i]+".seguro.chave_secreta", in, Integer.valueOf(s));

									//Decifra chave secreta
									byte[] rcvSecretKey = decrypt(readFileToBytes(args[i]+".seguro.chave_secreta", Integer.valueOf(s)), privateKey);
									//Chave secreta
									SecretKey originalKey = new SecretKeySpec(rcvSecretKey, 0, rcvSecretKey.length, "AES");
									//Decifra ficheiro
									decryptFile(args[i]+".seguro", originalKey, args[i]+".assinado");

									outStream.writeObject("-g");
									outStream.writeObject(args[i]+".seguro.assinatura");

									inStream.readObject();

									s = (String) inStream.readObject();
									System.out.println("mySNS: Tamanho do ficheiro " + args[i]+".seguro.assinatura" + " de " + s + " bytes");

									receiveFile(args[i]+".seguro.assinatura", in, Integer.valueOf(s));

									//Validacao do  ficheiro
									File assinatura = new File(args[i]+".seguro.assinatura");
									File assinado = new File(args[i]+".assinado");
									ReadFileVerifySign(publicKey, File_To_Array(assinatura), File_To_Array(assinado));

								} else {

									System.out.println();
									System.out.println("mySNS: Ficheiro " + args[i]+".assinado.cifrado não existe no servidor mySNSServer.");
									System.out.println();

								}

								outStream.writeObject("-g");
								outStream.writeObject(args[i]+".cifrado");

								if ((inStream.readObject()).equals("True")) {

									String s = (String) inStream.readObject();
									System.out.println("mySNS: ficheiro " + args[i]+".cifrado" + " existe no servidor.");
									System.out.println("mySNS: Tamanho do ficheiro " + args[i] + ".cifrado" + " de " + s + " bytes.");

									receiveFile(args[i]+".cifrado", in, Integer.valueOf(s));

									outStream.writeObject("-g");
									outStream.writeObject(args[i]+".chave_secreta."+utente);

									inStream.readObject();

									s = (String) inStream.readObject();
									System.out.println("mySNS: Tamanho do ficheiro " + args[i]+".chave_secreta." + utente + " de " + s + " bytes");

									receiveFile(args[i]+".chave_secreta."+utente, in, Integer.valueOf(s));

									//Decifra chave secreta
									byte[] rcvSecretKey = decrypt(readFileToBytes(args[i]+".chave_secreta."+utente, Integer.valueOf(s)), privateKey);
									//System.out.println(secretKeySTR);

									SecretKey originalKey = new SecretKeySpec(rcvSecretKey, 0, rcvSecretKey.length, "AES");

									decryptFile(args[i]+".cifrado", originalKey, args[i]);


								} else {

									System.out.println();
									System.out.println("mySNS: Ficheiro " + args[i]+".cifrado não existe no servidor mySNSServer.");
									System.out.println();

								}

								outStream.writeObject("-g");
								outStream.writeObject(args[i]+".assinado");

								if ((inStream.readObject()).equals("True")) {

									String s = (String) inStream.readObject();
									System.out.println("mySNS: " + args[i]+".assinado existe no servidor");
									System.out.println("mySNS: Tamanho do ficheiro " + args[i]+".assinado" + " de " + s + " bytes");

									receiveFile(args[i]+".assinado", in, Integer.valueOf(s));

									outStream.writeObject("-g");
									outStream.writeObject(args[i]+".assinatura."+medico);

									inStream.readObject();

									s = (String) inStream.readObject();
									System.out.println("mySNS: Tamanho do ficheiro " + args[i]+".assinatura." + medico + " de " + s + " bytes");

									receiveFile(args[i]+".assinatura."+medico, in, Integer.valueOf(s));

									File assinatura = new File(args[i]+".assinatura."+medico);
									File assinado = new File(args[i]+".assinado");

									ReadFileVerifySign(publicKey, File_To_Array(assinatura), File_To_Array(assinado));


								} else {

									System.out.println();
									System.out.println("mySNS: Ficheiro " + args[i]+".assinado não existe no servidor mySNSServer.");
									System.out.println();

								}


							} catch (ClassNotFoundException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							} catch (Exception e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}


						} 

						outStream.writeObject("Done");
						socket.close();

					} else {

						System.out.println("mySNS: Comando " + command + " não reconhecido.");

						socket.close();
					}

				} else {
					System.out.println("mySNS: Comando " + /* command + */ " não reconhecido.");
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
