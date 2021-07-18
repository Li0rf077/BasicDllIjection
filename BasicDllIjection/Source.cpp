#include <windows.h>
#include <tlhelp32.h>
#include <processthreadsapi.h>
#include <memoryapi.h>
#include <fileapi.h>
#include <tchar.h>
#include <libloaderapi.h>
#include <stdio.h>
#include <stdlib.h>

int findpidbyname()
{
    WCHAR notepad[20] = L"notepad.exe";
    HANDLE hsnap;
    PROCESSENTRY32 pe;
    
    // start notepad
    int status = system("start C:\\Windows\\system32\\notepad.exe");
   
    // Get snapshot of all processes running in system
    hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hsnap)
    {
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hsnap, &pe))
        {
            do
            {
                if (0 == wcscmp(notepad, pe.szExeFile))
                {
                    return pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(hsnap, &pe));
        }
    }
    return 0;
}

int main() {
    int success;
    int procID;
    HANDLE hprocess;
    HANDLE hthread;
    TCHAR  buffer[65] = L"C:\\Users\\eeran\\source\\repos\\Dll1\\x64\\Debug\\Dll1.dll";
    LPVOID b_alloc;
    LPVOID loadLibAddr;
    DWORD exitCode = 0;
    
    //get notepad's pid 
    procID = findpidbyname();
    
    // Get handle to calc
    hprocess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, procID);
    if (hprocess)
    {
        // Allocate space within notepad
        b_alloc = VirtualAllocEx(hprocess, 0, sizeof(buffer), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (b_alloc)
        {
            // Write to calc memory
            success = WriteProcessMemory(hprocess, b_alloc, buffer, sizeof(buffer), NULL);
            if (success)
            {
                // Find LoadLibrary address within our process
                HMODULE hmodule = GetModuleHandle(TEXT("kernel32.dll"));
                if (hmodule)
                {
                    loadLibAddr = GetProcAddress(hmodule, "LoadLibraryW");
                    if (loadLibAddr)
                    {
                        // Run the dll
                        hthread = CreateRemoteThread(hprocess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibAddr, b_alloc, 0, NULL);
                        if (hthread)
                        {
                            WaitForSingleObject(hthread, INFINITE);
                            GetExitCodeThread(hthread, &exitCode);
                            CloseHandle(hthread);
                        }
                    }
                }       
            }
        }
        CloseHandle(hprocess);
    }
}