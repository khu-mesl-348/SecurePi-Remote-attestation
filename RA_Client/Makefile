Remote_Attestation_Client: Remote_Attestation_Client.o
	gcc -o Remote_Attestation_Client Remote_Attestation_Client.o -ltspi -lcrypto -lssl
Remote_Attestation_Client.o: Remote_Attestation_Client.c
	gcc -c Remote_Attestation_Client.c

clean:
	rm -f Remote_Attestation_Client Remote_Attestation_Client.o
