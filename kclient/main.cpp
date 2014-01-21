// myspy.cpp : Defines the entry point for the console application.
//
#include "client.h"
#include <stdio.h>

int main(int argc, char* argv[])
{
	if (argc != 4) {
		printf("Wrong num args, should be 4");
		exit(-1);
	}

	if (strncmp(argv[1], "-start", strlen("-start") + 1) == 0) {
		char *clientId = argv[2];
		char *authId = argv[3];
		ClientDrvStart(clientId, authId);
	} else if (strcmp(argv[1], "-stop") == 0) {
		char *clientId = argv[2];
		char *authId = argv[3];
		ClientDrvStop(clientId, authId);
	} else {
		printf("unknown parameter=%s", argv[1]);
		exit(-1);
	}

	return 0;
}

