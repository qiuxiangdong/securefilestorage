-----------------------------------
File Upload /Documents/DataOwner
compile: gcc -o fileuploadcl FileUploadClient.c common.c -L. -lgmp -lpbc
run ./fileuploadcl 192.168.1.4
command line input
1. file.txt
2. Keyword list


------------------------------------
TrapDoorGen /Documents/DataUser
compile: gcc -o Trapclient TrapdoorGen.c common.c -L. -lgmp -lpbc
run ./Trapclient 192.168.1.4
commandline input
1. Trapdoor keyword search

