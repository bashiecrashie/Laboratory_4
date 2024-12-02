compiler=gcc
compiler_flags=-lssl -lcrypto
client_source=client.c
server_source=server.c
client_build=lab_4_client
server_build=lab_4_server

all: client server

client: $(client_source)
	$(compiler) $(client_source) -o $(client_build) $(compiler_flags)

server: $(server_source)
	$(compiler) $(server_source) -o $(server_build) $(compiler_flags)

