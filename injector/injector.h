#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

#define log(text, ...) printf(text, __VA_ARGS__);
#define err(text, ...) printf(text, __VA_ARGS__); return NULL;

DWORD get_pid(const std::wstring& proc_name) {

	PROCESSENTRY32 proc_entry;
	proc_entry.dwSize = sizeof(proc_entry);

	auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL); // snapshot of process list
	if (!snapshot) { err("[!] Failed to take process snapshot: %d\n", GetLastError()); }

	Process32First(snapshot, &proc_entry); // check first proc in snapshot
	if (!proc_name.compare(proc_entry.szExeFile)) {
		CloseHandle(snapshot);
		return proc_entry.th32ProcessID;
	}

	while (Process32Next(snapshot, &proc_entry)) { // iterate rest of the snapshot
		if (!proc_name.compare(proc_entry.szExeFile)) {
			CloseHandle(snapshot);
			return proc_entry.th32ProcessID;
		}
	}

	CloseHandle(snapshot);
	return 0;
}

bool inject(const std::wstring& proc_name, const std::wstring& dll_name) {

	log("[+] Injecting %ws into %ws\n", dll_name.c_str(), proc_name.c_str());

	auto pid = get_pid(proc_name);
	if (!pid) { err("[!] Failed to get process ID\n"); }

	auto proc = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
	if (!proc) { err("[!] Failed to get process handle: %d\n", GetLastError()); }
	
	log("[+] Got handle to process %ws\n", proc_name.c_str());

	auto kernel32 = GetModuleHandleA("kernel32.dll");
	if (!kernel32) { err("[!] Failed to get kernel32.dll handle: %d\n", GetLastError()); }

	auto load_library = GetProcAddress(kernel32, "LoadLibraryW");
	if (!load_library) { err("[!] Failed to get LoadLibraryW address: %d\n", GetLastError()); }
	
	log("[+] Got LoadLibraryW address: 0x%p\n", load_library);

	wchar_t dll_path[MAX_PATH];
	GetFullPathName(dll_name.c_str(), MAX_PATH, dll_path, NULL); // get full dll path
	
	auto alloc = VirtualAllocEx(proc, NULL, sizeof(dll_path), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!alloc) { err("[!] Failed to allocate memory: %d\n", GetLastError()); }
	
	log("[+] Allocated memory at: 0x%p\n", alloc);

	WriteProcessMemory(proc, alloc, dll_path, sizeof(dll_path), NULL);
	log("[+] Wrote dll path to allocated memory\n");

	// call LoadLibraryW within target and pass the dll path we wrote to allocated memory
	auto thread = CreateRemoteThread(proc, NULL, NULL, (LPTHREAD_START_ROUTINE)load_library, alloc, NULL, NULL);
	if (!thread) { err("[!] Failed to create remote thread: %d\n", GetLastError()); }

	log("[+] Called LoadLibraryW from remote thread\n");

	WaitForSingleObject(thread, INFINITE); // wait for thread to return

	log("[+] Remote thread returned\n");

	CloseHandle(proc);
	return true;
}
