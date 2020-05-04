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
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <aclapi.h>
#include <accctrl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <lm.h>
//#include <winternl.h>
#include <wchar.h>
#include "list_tokens.h"
#include "token_info.h"
#include "handle_arguments.h"

extern int gProcessId;
typedef LONG   NTSTATUS;
typedef VOID   *POBJECT;
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemExtendedProcessInformation = 57
} SYSTEM_INFORMATION_CLASS;

typedef enum _OBJECT_INFORMATION_CLASS{
   ObjectBasicInformation,
      ObjectNameInformation,
      ObjectTypeInformation,
      ObjectAllTypesInformation,
      ObjectHandleInformation
} OBJECT_INFORMATION_CLASS;

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;


/*

typedef struct _SYSTEM_HANDLE {
   ULONG           uIdProcess;
   UCHAR           ObjectType;
   UCHAR           Flags;
   USHORT          Handle;
   POBJECT         pObject;
   ACCESS_MASK     GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
   ULONG                   uCount;
   SYSTEM_HANDLE   Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

*/
typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[48];
	UNICODE_STRING ImageName;
	long BasePriority;
	HANDLE UniqueProcessId;
	PVOID Reserved2;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID Reserved3;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG Reserved4;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	PVOID Reserved5;
	SIZE_T QuotaPagedPoolUsage;
	PVOID Reserved6;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

/*
typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	BYTE Reserved1[52];
	PVOID Reserved2[3];
	HANDLE UniqueProcessId;
	PVOID Reserved3;
	ULONG HandleCount;
	BYTE Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;
*/
typedef struct _VM_COUNTERS {
	// the following was inferred by painful reverse engineering
	SIZE_T		   PeakVirtualSize;	// not actually
	SIZE_T         PageFaultCount;
	SIZE_T         PeakWorkingSetSize;
	SIZE_T         WorkingSetSize;
	SIZE_T         QuotaPeakPagedPoolUsage;
	SIZE_T         QuotaPagedPoolUsage;
	SIZE_T         QuotaPeakNonPagedPoolUsage;
	SIZE_T         QuotaNonPagedPoolUsage;
	SIZE_T         PagefileUsage;
	SIZE_T         PeakPagefileUsage;
	SIZE_T         VirtualSize;		// not actually
} VM_COUNTERS;
typedef struct _CLIENT_ID {
	DWORD          UniqueProcess;
	DWORD          UniqueThread;
} CLIENT_ID;
typedef enum _KWAIT_REASON
{
	Executive = 0,
	FreePage = 1,
	PageIn = 2,
	PoolAllocation = 3,
	DelayExecution = 4,
	Suspended = 5,
	UserRequest = 6,
	WrExecutive = 7,
	WrFreePage = 8,
	WrPageIn = 9,
	WrPoolAllocation = 10,
	WrDelayExecution = 11,
	WrSuspended = 12,
	WrUserRequest = 13,
	WrEventPair = 14,
	WrQueue = 15,
	WrLpcReceive = 16,
	WrLpcReply = 17,
	WrVirtualMemory = 18,
	WrPageOut = 19,
	WrRendezvous = 20,
	Spare2 = 21,
	Spare3 = 22,
	Spare4 = 23,
	Spare5 = 24,
	WrCalloutStack = 25,
	WrKernel = 26,
	WrResource = 27,
	WrPushLock = 28,
	WrMutex = 29,
	WrQuantumEnd = 30,
	WrDispatchInt = 31,
	WrPreempted = 32,
	WrYieldExecution = 33,
	WrFastMutex = 34,
	WrGuardedMutex = 35,
	WrRundown = 36,
	MaximumWaitReason = 37
} KWAIT_REASON;


typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	long Priority;
	LONG BasePriority;
	ULONG ContextSwitchCount;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
#ifdef _WIN64
	ULONG Reserved[4];
#endif
}SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;
typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION
{
	SYSTEM_THREAD_INFORMATION ThreadInfo;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID Win32StartAddress;
	PVOID TebAddress; /* This is only filled in on Vista and above */
	ULONG Reserved1;
	ULONG Reserved2;
	ULONG Reserved3;
} SYSTEM_EXTENDED_THREAD_INFORMATION, * PSYSTEM_EXTENDED_THREAD_INFORMATION;
typedef struct _SYSTEM_EXTENDED_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	long BasePriority;
	ULONG SessionId;// UniqueProcessId;
	ULONG UniqueProcessId;// InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG InheritedFromUniqueProcessId;
	PVOID PageDirectoryBase;
	VM_COUNTERS VirtualMemoryCounters;
	SIZE_T PrivatePageCount;
	IO_COUNTERS IoCounters;
	SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1];
	
} SYSTEM_EXTENDED_PROCESS_INFORMATION, * PSYSTEM_EXTENDED_PROCESS_INFORMATION;

#define STATUS_SUCCESS                          ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH             ((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_OVERFLOW                  ((NTSTATUS)0x80000005L)
#define SystemHandleInformation                 16
#define SystemProcessInformation				5

typedef NTSTATUS (WINAPI *NTQUERYSYSTEMINFORMATION)(DWORD SystemInformationClass, 
                                                    PVOID SystemInformation,
                                                    DWORD SystemInformationLength, 
                                                    PDWORD ReturnLength);

typedef NTSTATUS (WINAPI *NTQUERYOBJECT)(HANDLE ObjectHandle, 
                                         OBJECT_INFORMATION_CLASS ObjectInformationClass, 
                                         PVOID ObjectInformation,
                                         DWORD Length, 
                                         PDWORD ResultLength);

NTQUERYOBJECT              NtQueryObject ;
NTQUERYSYSTEMINFORMATION   NtQuerySystemInformation; 

LPWSTR			GetObjectInfo(HANDLE hObject, OBJECT_INFORMATION_CLASS objInfoClass);

typedef UNICODE_STRING OBJECT_NAME_INFORMATION;
typedef UNICODE_STRING *POBJECT_NAME_INFORMATION;

LPWSTR GetObjectInfo(HANDLE hObject, OBJECT_INFORMATION_CLASS objInfoClass)
{
   LPWSTR data = NULL;
   DWORD dwSize = sizeof(OBJECT_NAME_INFORMATION);
   POBJECT_NAME_INFORMATION pObjectInfo = (POBJECT_NAME_INFORMATION) malloc(dwSize);
   
   NTSTATUS ntReturn = NtQueryObject(hObject, objInfoClass, pObjectInfo, dwSize, &dwSize);   
   if((ntReturn == STATUS_BUFFER_OVERFLOW) || (ntReturn == STATUS_INFO_LENGTH_MISMATCH)){
      pObjectInfo =realloc(pObjectInfo ,dwSize);
      ntReturn = NtQueryObject(hObject, objInfoClass, pObjectInfo, dwSize, &dwSize);
   }
   if((ntReturn >= STATUS_SUCCESS) && (pObjectInfo->Buffer != NULL))
   {
      data = (LPWSTR)calloc(pObjectInfo->Length, sizeof(WCHAR));
      CopyMemory(data, pObjectInfo->Buffer, pObjectInfo->Length);
   }
   free(pObjectInfo);
   return data;
}


static int compare_token_names(const unique_user_token *a, const unique_user_token *b)
{
	return _stricmp(a->username, b->username);
}
SavedToken* get_token_list(DWORD* num_tokens_enum, TOKEN_PRIVS* token_privs)
{
	DWORD total = 0, i, j, num_tokens = 0, token_list_size = BUF_SIZE, dwSize = sizeof(SYSTEM_HANDLE_INFORMATION), dwError;
	HANDLE process, hObject;
	PSYSTEM_PROCESS_INFORMATION pProcessInfo = NULL;
	PSYSTEM_PROCESS_INFORMATION original_pProcessInfo = NULL;
	NTSTATUS ntReturn;
	BOOL bMoreProcesses = TRUE;

	LPVOID TokenPrivilegesInfo[BUF_SIZE];
	DWORD returned_privileges_length, returned_name_length;
	char privilege_name[BUF_SIZE];
	HANDLE hObject2 = NULL;
	TOKEN_TYPE Type;
	TCHAR nameProc[1024];
	SavedToken* token_list = (SavedToken*)calloc(token_list_size, sizeof(SavedToken));
	*num_tokens_enum = 0;
	DWORD Size=0;

	token_privs->SE_ASSIGNPRIMARYTOKEN_PRIVILEGE = FALSE;
	token_privs->SE_CREATE_TOKEN_PRIVILEGE = FALSE;
	token_privs->SE_TCB_PRIVILEGE = FALSE;
	token_privs->SE_TAKE_OWNERSHIP_PRIVILEGE = FALSE;
	token_privs->SE_BACKUP_PRIVILEGE = FALSE;
	token_privs->SE_RESTORE_PRIVILEGE = FALSE;
	token_privs->SE_DEBUG_PRIVILEGE = FALSE;
	token_privs->SE_IMPERSONATE_PRIVILEGE = FALSE;
	token_privs->SE_RELABEL_PRIVILEGE = FALSE;
	token_privs->SE_LOAD_DRIVER_PRIVILEGE = FALSE;

	// Enable debug privs if possible
	TryEnableDebugPriv(NULL);
	TryEnableAssignPrimaryPriv(NULL);
	OpenProcessToken(GetCurrentProcess(), GENERIC_ALL/*MAXIMUM_ALLOWED*/, &hObject);
	has_impersonate_priv(hObject);

	NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation");
	NtQueryObject = (NTQUERYOBJECT)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQueryObject");
	dwSize = 256 * 1000;

	
	pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)malloc(dwSize);
	ntReturn = NtQuerySystemInformation(SystemProcessInformation, pProcessInfo, dwSize, &dwSize);

	while (ntReturn == STATUS_INFO_LENGTH_MISMATCH) {
		free(pProcessInfo);
		pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)malloc(dwSize);
		ntReturn = NtQuerySystemInformation(SystemProcessInformation, pProcessInfo, dwSize, &dwSize);
	}

	original_pProcessInfo = pProcessInfo;

	if (ntReturn == STATUS_SUCCESS)
	{
		while (bMoreProcesses)
		{
			if (pProcessInfo->NextEntryOffset == 0)
				bMoreProcesses = FALSE;

			process = OpenProcess(MAXIMUM_ALLOWED, FALSE, (DWORD)pProcessInfo->UniqueProcessId);
			//GetProcessImageFileName(process, nameProc, sizeof(nameProc) / sizeof(*nameProc));
			if ((gProcessId != -1) && (pProcessInfo->UniqueProcessId != gProcessId))
			{
				pProcessInfo = (PSYSTEM_EXTENDED_PROCESS_INFORMATION)((ULONG_PTR)pProcessInfo + pProcessInfo->NextEntryOffset);

				continue;
			}
			
			for (i = 0; i < pProcessInfo->HandleCount; i++)
			{
				if (process != INVALID_HANDLE_VALUE)
				{
					hObject = NULL;

					if (DuplicateHandle(process, (HANDLE)((i + 1) * 8),
						GetCurrentProcess(), &hObject, MAXIMUM_ALLOWED, FALSE, 0x02) != FALSE)
					{
						LPWSTR lpwsType = NULL;
						lpwsType = GetObjectInfo(hObject, ObjectTypeInformation);
						if ((lpwsType != NULL) && !wcscmp(lpwsType, L"Token") && ImpersonateLoggedOnUser(hObject) != 0)
						{
							// ImpersonateLoggedOnUser() always returns true. Need to check whether impersonated token kept impersonate status - failure degrades to identification
							// also revert to self after getting new token context
							// only process if it was impersonation or higher
							OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, TRUE, &hObject2);
							RevertToSelf();
							if (is_impersonation_token(hObject2))
							{
								// Reallocate space if necessary
								if (*num_tokens_enum >= token_list_size)
								{
									token_list_size *= 2;
									token_list = (SavedToken*)realloc(token_list, token_list_size * sizeof(SavedToken));
									if (!token_list)
										goto cleanup;
								}
								token_list[*num_tokens_enum].token = hObject;
								get_domain_username_from_token(hObject, token_list[*num_tokens_enum].username);
								
								GetTokenInformation(hObject, TokenType, &Type, sizeof(TOKEN_TYPE), &Size);
								
								(*num_tokens_enum)++;
								
								/*if (GetTokenInformation(hObject, TokenPrivileges, TokenPrivilegesInfo, BUF_SIZE, &returned_privileges_length))
								{
									if (((TOKEN_PRIVILEGES*)TokenPrivilegesInfo)->PrivilegeCount > 0)
										for (j = 0; j < ((TOKEN_PRIVILEGES*)TokenPrivilegesInfo)->PrivilegeCount; j++)
										{
											returned_name_length = BUF_SIZE;
											LookupPrivilegeNameA(NULL, &(((TOKEN_PRIVILEGES*)TokenPrivilegesInfo)->Privileges[j].Luid), privilege_name, &returned_name_length);
											if (strcmp(privilege_name, "SeAssignPrimaryTokenPrivilege") == 0)
											{
												token_privs->SE_ASSIGNPRIMARYTOKEN_PRIVILEGE = TRUE;
											}
											else if (strcmp(privilege_name, "SeCreateTokenPrivilege") == 0)
											{
												token_privs->SE_CREATE_TOKEN_PRIVILEGE = TRUE;
											}
											else if (strcmp(privilege_name, "SeTcbPrivilege") == 0)
											{
												token_privs->SE_TCB_PRIVILEGE = TRUE;
											}
											else if (strcmp(privilege_name, "SeTakeOwnershipPrivilege") == 0)
											{
												token_privs->SE_TAKE_OWNERSHIP_PRIVILEGE = TRUE;
											}
											else if (strcmp(privilege_name, "SeBackupPrivilege") == 0)
											{
												token_privs->SE_BACKUP_PRIVILEGE = TRUE;
											}
											else if (strcmp(privilege_name, "SeRestorePrivilege") == 0)
											{
												token_privs->SE_RESTORE_PRIVILEGE = TRUE;
											}
											else if (strcmp(privilege_name, "SeDebugPrivilege") == 0)
											{
												token_privs->SE_DEBUG_PRIVILEGE = TRUE;
											}
											else if (strcmp(privilege_name, "SeImpersonatePrivilege") == 0)
											{
												token_privs->SE_IMPERSONATE_PRIVILEGE = TRUE;
											}
											else if (strcmp(privilege_name, "SeRelabelPrivilege") == 0)
											{
												token_privs->SE_RELABEL_PRIVILEGE = TRUE;
											}
											else if (strcmp(privilege_name, "SeLoadDriverPrivilege") == 0)
											{
												token_privs->SE_LOAD_DRIVER_PRIVILEGE = TRUE;
											}
										}
								}*/

								(*num_tokens_enum)++;
							}
							CloseHandle(hObject2);
						}
						else
							CloseHandle(hObject);
					}
				}
			}

			// Also process primary
			// if has impersonate privs, only needs read access
			process = OpenProcess(MAXIMUM_ALLOWED, FALSE, (DWORD)pProcessInfo->UniqueProcessId);
			dwError = OpenProcessToken(process, MAXIMUM_ALLOWED, &hObject);

			if (dwError != 0 && ImpersonateLoggedOnUser(hObject) != 0)
			{
				// ImpersonateLoggedOnUser() always returns true. Need to check whether impersonated token kept impersonate status - failure degrades to identification
				// also revert to self after getting new token context
				// only process if it was impersonation or higher
				OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, TRUE, &hObject2);
				RevertToSelf();
				if (is_impersonation_token(hObject2))
				{
					token_list[*num_tokens_enum].token = hObject;
					get_domain_username_from_token(hObject, token_list[*num_tokens_enum].username);
					
					GetTokenInformation(hObject, TokenType, &Type, sizeof(TOKEN_TYPE), &Size);
					
					(*num_tokens_enum)++;
					(*num_tokens_enum)++;
					
					/*if (GetTokenInformation(hObject, TokenPrivileges, TokenPrivilegesInfo, BUF_SIZE, &returned_privileges_length))
					{
						for (i = 0; i < ((TOKEN_PRIVILEGES*)TokenPrivilegesInfo)->PrivilegeCount; i++)
						{
							returned_name_length = BUF_SIZE;
							LookupPrivilegeNameA(NULL, &(((TOKEN_PRIVILEGES*)TokenPrivilegesInfo)->Privileges[i].Luid), privilege_name, &returned_name_length);
							if (strcmp(privilege_name, "SeAssignPrimaryTokenPrivilege") == 0)
							{
								token_privs->SE_ASSIGNPRIMARYTOKEN_PRIVILEGE = TRUE;
							}
							else if (strcmp(privilege_name, "SeCreateTokenPrivilege") == 0)
							{
								token_privs->SE_CREATE_TOKEN_PRIVILEGE = TRUE;
							}
							else if (strcmp(privilege_name, "SeTcbPrivilege") == 0)
							{
								token_privs->SE_TCB_PRIVILEGE = TRUE;
							}
							else if (strcmp(privilege_name, "SeTakeOwnershipPrivilege") == 0)
							{
								token_privs->SE_TAKE_OWNERSHIP_PRIVILEGE = TRUE;
							}
							else if (strcmp(privilege_name, "SeBackupPrivilege") == 0)
							{
								token_privs->SE_BACKUP_PRIVILEGE = TRUE;
							}
							else if (strcmp(privilege_name, "SeRestorePrivilege") == 0)
							{
								token_privs->SE_RESTORE_PRIVILEGE = TRUE;
							}
							else if (strcmp(privilege_name, "SeDebugPrivilege") == 0)
							{
								token_privs->SE_DEBUG_PRIVILEGE = TRUE;
							}
							else if (strcmp(privilege_name, "SeImpersonatePrivilege") == 0)
							{
								token_privs->SE_IMPERSONATE_PRIVILEGE = TRUE;
							}
							else if (strcmp(privilege_name, "SeRelabelPrivilege") == 0)
							{
								token_privs->SE_RELABEL_PRIVILEGE = TRUE;
							}
							else if (strcmp(privilege_name, "SeLoadDriverPrivilege") == 0)
							{
								token_privs->SE_LOAD_DRIVER_PRIVILEGE = TRUE;
							}
						}
					}*/
				}

				CloseHandle(hObject2);
			}
			pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pProcessInfo + pProcessInfo->NextEntryOffset);

			//pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG)pProcessInfo + (ULONG)pProcessInfo->NextEntryOffset);
		}
	}

cleanup:
	free(original_pProcessInfo);

	return token_list;
}


void list_unique_tokens(TOKEN_ORDER token_order)
{
	DWORD num_unique_tokens = 0, num_tokens = 0, i;
	unique_user_token *uniq_tokens = calloc(BUF_SIZE*4, sizeof(unique_user_token));
	SavedToken *token_list = NULL;
	BOOL bTokensAvailable = FALSE, bPrivilegesAvailable = FALSE;
	TOKEN_PRIVS token_privs;
	// Enumerate tokens
	output_status_string("[*] Enumerating tokens\n");
	grepable_mode = TRUE;
	token_list = get_token_list(&num_tokens, &token_privs);

	if (!token_list)
	{
		output_status_string("[-] Failed to enumerate tokens with error code: %d\n", GetLastError());
		return;
	}

	// Process all tokens to get determinue unique names and delegation abilities
	for (i=0;i<num_tokens;i++)
	if (token_list[i].token)
	{
		process_user_token(token_list[i].token, uniq_tokens, &num_unique_tokens, token_order);
		CloseHandle(token_list[i].token);
	}

	if (token_list)
		free(token_list);

	// Sort by name and then display all delegation and impersonation tokens
	qsort(uniq_tokens, num_unique_tokens, sizeof(unique_user_token), compare_token_names);

	//output_status_string("[*] Listing unique users found\n");
	

	for (i=0;i<num_unique_tokens;i++)
	if (uniq_tokens[i].delegation_available)
	{
		bTokensAvailable = TRUE;
		
			output_string("=>%s\n", uniq_tokens[i].username);
	}

	for (i=0;i<num_unique_tokens;i++)
	if (!uniq_tokens[i].delegation_available && uniq_tokens[i].impersonation_available)
	{
		
		bTokensAvailable = TRUE;
		output_string("=>%s\n", uniq_tokens[i].username);
	}

	if (!bTokensAvailable)
		output_status_string("[-] No tokens available\n");

	bTokensAvailable = FALSE;

	
	free(uniq_tokens);
}

void process_user_token(HANDLE token, unique_user_token *uniq_tokens, DWORD *num_tokens, TOKEN_ORDER token_order)
{
	DWORD i, j, num_groups=0;
	char *full_name=NULL, **group_name_array = NULL;
	BOOL user_exists = FALSE;

	// If token is NULL then return
	if (!token)
		return;

	// Get token user or groups
	if (token_order == BY_USER)
	{
		full_name = calloc(BUF_SIZE, sizeof(char));
		num_groups = 1;
		if (!get_domain_username_from_token(token, full_name))
			goto cleanup;
	}
	else if (token_order == BY_GROUP)
		if (!get_domain_groups_from_token(token, &group_name_array, &num_groups))
			goto cleanup;
	
	for (i=0;i<num_groups;i++)
	{
		if (token_order == BY_GROUP)
			full_name = (char*)group_name_array[i];

		// Check
		if (!_stricmp("None", strchr(full_name, '\\') + 1) || !_stricmp("Everyone", strchr(full_name, '\\') + 1)
			|| !_stricmp("LOCAL", strchr(full_name, '\\') + 1) || !_stricmp("NULL SID", strchr(full_name, '\\') + 1)
			|| !_stricmp("CONSOLE LOGON", strchr(full_name, '\\') + 1))
			continue;

		// Check to see if username has been seen before
		for (j=0;j<*num_tokens;j++)
		{
			// If found then increment the number and set delegation flag if appropriate
			if (!_stricmp(uniq_tokens[j].username, full_name))
			{
				uniq_tokens[j].token_num++;
				user_exists = TRUE;
				if (is_delegation_token(token))
					uniq_tokens[j].delegation_available = TRUE;
				if (is_impersonation_token(token))
					uniq_tokens[j].impersonation_available = TRUE;
				break;
			}
		}

		// If token user has not been seen yet then create new entry
		if (!user_exists)
		{
			strcpy(uniq_tokens[*num_tokens].username, full_name);
			uniq_tokens[*num_tokens].token_num = 1;
			uniq_tokens[*num_tokens].delegation_available = FALSE;
			uniq_tokens[*num_tokens].impersonation_available = FALSE;

			if (is_delegation_token(token))
				uniq_tokens[*num_tokens].delegation_available = TRUE;
			if (is_impersonation_token(token))
				uniq_tokens[*num_tokens].impersonation_available = TRUE;

			(*num_tokens)++;
		}
		else
			user_exists = FALSE;

		// Cleanup
		if (token_order == BY_GROUP && group_name_array[i])
			free(group_name_array[i]);
	}

	// Cleanup
cleanup:
	if (token_order == BY_GROUP && group_name_array)
		free(group_name_array);
	else if (token_order == BY_USER && full_name)
		free(full_name);
}




