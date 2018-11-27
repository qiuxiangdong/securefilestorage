--------------------------------------------
All the code is in Documents folder
--------------------------------------------
#Run the server to upload file
gcc -o server server.c common.c -L. -lgmp -lpbc `mysql_config --cflags --libs`
./server
--------------------------------------------
#trapgen
gcc -o tpgser TrapGenServer.c common.c -L. -lgmp -lpbc `mysql_config --cflags --libs`
./tpgser


