Remote_Attestation_Server: Remote_Attestation_Server.o
	gcc -o Remote_Attestation_Server Remote_Attestation_Server.o -lcrypto -lssl
Remote_Attestation_Server.o: Remote_Attestation_Server.c
	gcc -c Remote_Attestation_Server.c

clean:
	rm -f Remote_Attestation_Server Remote_Attestation_Server.o
