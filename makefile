all:
	g++ public_server.cpp -o public_server
	g++ https.cpp -lssl -lcrypto -o https