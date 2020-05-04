#define _CRT_SECURE_NO_DEPRECATE 1
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "handle_arguments.h"


int gProcessId=-1;
int main(int argc, char *argv[])
{
	hINPUT = stdin;
	hOUTPUT = stdout;
	handle_options(argc,argv);
	exit(0);
}
