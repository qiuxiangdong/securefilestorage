# Secure-File-Storage-Cloud

Attribute based secure file storage on cloud<br />
###Steps to Run
### 1. Setup the TA- to generate the MSK
Compile: gcc -o setup setup.c -L. -lpbc -lgmp <br />
Run: ./setup

### 2. Run the server on TA for Data owners to request for unique private key (server runs infinitely)
Compile: gcc -o PKGen PKGenServer.c common.c -L. -lpbc -lgmp<br />
Run: ./PKGen<br />
Data owner requests for Private Key by sending attributelist<br />
Compile: gcc -o client client.c common.c -L. -lpbc -lgmp<br />
Run: ./client 192.168.1.5<br />
Command line input<br />
a. attributelist.txt<br />


### 3. MetaData server is run which actually provides file storage
Run the server to upload file<br />
Compile: gcc -o server server.c common.c -L. -lgmp -lpbc `mysql_config --cflags --libs` <br />
Run: ./server<br />
Data owner uploads the encrypted file using the private key obtained by TA <br />
Compile: gcc -o fileuploadcl FileUploadClient.c common.c -L. -lgmp -lpbc <br />
Run ./fileuploadcl 192.168.1.5(IP address of TA) <br />
command line input<br />
File.txt (file to upload)<br />
Keyword list<br />

### 4. Data user requests the server for file using a keyword list. If the attributes of the user matches and keyword list matches the user gets access to the file.
Running the Trapdoor server:<br />
Compile: gcc -o tpgser TrapGenServer.c common.c -L. -lgmp -lpbc `mysql_config --cflags --libs` <br />
Run: ./tpgser <br />

compile: gcc -o Trapclient TrapdoorGen.c common.c -L. -lgmp -lpbc <br />
run ./Trapclient 192.168.1.4(IP address of metadata server) <br />
Command line input <br />
1. Trapdoor keyword search <br />










