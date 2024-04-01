Seguranca Inforamtica(22/23)

Anotacoes:
	Keystore: keystore.userCloud; password: admin123; Alias: joao, alice

Compilar 
- Servidor
	javac src/mySNSServer.java -d bin

- Cliente
	javac src/mySNS.java -d bin
	
Correr
- Servidor
	java -cp bin mySNSServer
	
Comandos
- Cliente:	

	Utilizador user envia para a sua pasta no servidor ficheiros assinados, cifrados ou assinados.cifrados:
		java -cp bin mySNS -a 10.0.2.15:23456 -m joao -u matilde -sa si.trab1.2023.2024v3.pdf
		java -cp bin mySNS -a 10.0.2.15:23456 -m joao -u matilde -sc si.trab1.2023.2024v3.pdf
		java -cp bin mySNS -a 10.0.2.15:23456 -m joao -u matilde -se si.trab1.2023.2024v3.pdf
	
	Utilizador joao pede para receber os ficheiros que estão na sua pasta:
		java -cp bin mySNS -a 10.0.2.15:23456 -m joao -u matilde -g si.trab1.2023.2024v3.pdf
		
	