#include <iostream>
#include <windows.h>
#include <tlhelp32.h>

int findProcessID(wchar_t processName[]);

int main()
{
	// Declare a wchar_t array to put process name.
	wchar_t processName[100] = L"waitKey.exe";

	// Get the PID.
	printf("1. Get the process ID\n");
	int pid = findProcessID(processName);
	if (pid < 0) {
		printf("\t[FAILURE]  Not found the process \"%ls\".\n", processName);
		system("PAUSE");
		return 0;
	}
	printf("\t[SUCCESS]  The process \"%ls\" is found. And PID is %d.\n", processName, pid);

	// Get the right to operate in target.
	printf("2. Get the handle to the process\n");
	HANDLE pHandle = OpenProcess(
		PROCESS_CREATE_THREAD |        // Permission to create threads
		PROCESS_QUERY_INFORMATION |    // Permission to get information about the process, such as its exit code, priority.
		PROCESS_VM_OPERATION |         // Permission to manipulate the memory in the process. (VirtualProtectEx and WriteProcessMemory can be used.)
		PROCESS_VM_READ |              // Permission to read the memory in the process. (ReadProcessMemory can be used.)
		PROCESS_VM_WRITE,              // Permission to write the memory in the process. (WriteProcessMemory can be used.)
		false, pid);
	if (pHandle == NULL) {
		printf("\t[FAILURE]  Doesn't obtain the handle to the process (%ls, %d).\n", processName, pid);
		system("PAUSE");
		return 0;
	}
	printf("\t[SUCCESS]  The handle to the process (%ls, %d)  is 0x%08X.\n", processName, pid, pHandle);

	// Allocate the memory for the injected dll name in process.
	printf("3. Allocate the memory for the dll path\n");
	// Use full path to dll.
	const char *dllPath = "C:\\Users\\wrxue\\source\\repos\\injection\\dllMainAndFun.dll";
	LPVOID dllAddr = VirtualAllocEx(
		pHandle,                    // The handle to a process.
		NULL,                       // The pointer that specifies a desired starting address for the region of pages.
		strlen(dllPath),            // The size of the memory we need.
		MEM_RESERVE | MEM_COMMIT,   // Allocation type.
		PAGE_EXECUTE_READWRITE);    // The memory protection for the region of pages to be allocated.
	if (dllAddr == NULL) {
		printf("\t[FAILURE]  Allocate memory failed.\n");
		system("PAUSE");
		return 0;
	}
	printf("\t[SUCCESS]  Successfully allocate memory at 0x%08X.\n", dllAddr);

	// Write the dll path to the memory just allocated.
	printf("4. Write the dll path to the memory\n");
	// WriteProcessMemory(
	//	pHandle,         // The handle to a process.
	//	dllAddr,         // A pointer to the base address in the specified process to which data is written.
	//	dllPath,         // A pointer to the buffer that contains data to be written in the dllAddr.
	//	strlen(dllPath), // The number of bytes to be written to the specified process.
	//	NULL)            // If this is NULL, the parameter is ignored.
	if (WriteProcessMemory(pHandle, dllAddr, dllPath, strlen(dllPath), NULL) == FALSE) {
		printf("\t[FAILURE]  Failed to write the dll path into memory.\n");
		system("PAUSE");
		return 0;
	}
	printf("\t[SUCCESS]  The dll path is successfully written into the memory.\n");
	
	// Get the address of the function "LoadLibraryA".
	printf("5. Get address of \"LoadLibraryA\"\n");
	// GetModuleHandle : Retrieves a module handle for the specified module. 
	// The module must have been loaded by the calling process.
	// GetProcAddress : Retrieves the address of an exported function 
	// or variable from the specified dynamic-link library (DLL).
	// Function address has nothing to do with the target.
	LPVOID loadLibraryAAddr = (LPVOID)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");
	if (loadLibraryAAddr == NULL) {
		printf("\t[FAILURE]  LoadLibraryA is not found.\n");
		system("PAUSE");
		return 0;
	}
	printf("\t[SUCCESS]  LoadLibraryA is found at 0x%08X.\n", loadLibraryAAddr);

	// Create remote thread in the target!!
	printf("6. Create remote thread\n");
	HANDLE remoteThreadHandle = CreateRemoteThread(
		pHandle,                                    // A handle to the process in which the thread is to be created.
		NULL,										
		0,                                          // The initial size of the stack, in bytes. 0 for default size.
		(LPTHREAD_START_ROUTINE)loadLibraryAAddr,   // Represents the starting address of the thread in the remote process.
		(LPVOID *)dllAddr,                          // A pointer to a variable to be passed to the thread function.
		0,                                          // 0 for the thread runs immediately after creation.
		NULL);                                      // A pointer to a variable that receives the thread identifier.
	if (remoteThreadHandle == NULL) {
		printf("\t[FAILURE]  Remote thread creation failed.\n");
		system("PAUSE");
		return 0;
	}
	printf("\t[SUCCESS]  The handle to the remote thread is 0x%08X.\n", remoteThreadHandle);


	system("PAUSE");
	return 0;

}

int findProcessID(wchar_t processName[]) {
	// Enumerate all processes.
	PROCESSENTRY32 entry;

	// dwSize: The size of the structure, in bytes. 
	// Before calling the Process32First function, 
	// set this member to sizeof(PROCESSENTRY32). 
	// If you do not initialize dwSize, Process32First fails.
	entry.dwSize = sizeof(PROCESSENTRY32);

	// Includes all processes in the system in the snapshot.
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE) {
		while (Process32Next(snapshot, &entry) == TRUE) {
			if (wcscmp(entry.szExeFile, processName) == 0) {
				// Match the process name.
				return entry.th32ProcessID;
			}
		}
	}
	return -1;
}