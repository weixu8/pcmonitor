// myspy.cpp : Defines the entry point for the console application.
//
#include "client.h"
#include <stdio.h>

int main(int argc, char* argv[])
{
	if (argc != 2) {
		printf("Wrong num args, should be 1: usage: eyeclient.exe -start, or eyeclient.exe -stop");
		exit(-1);
	}

	if (strcmp(argv[1], "-start") == 0) {
		ClientDrvStart();
	} else if (strcmp(argv[1], "-stop") == 0) {
		ClientDrvStop();
	} else {
		printf("unknown parameter=%s", argv[1]);
		exit(-1);
	}

	return 0;
}

