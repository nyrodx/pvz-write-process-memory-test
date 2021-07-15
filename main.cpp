#include <iostream>
#include <windows.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <vector>
using namespace std;

DWORD GetModuleBaseAddress(TCHAR* lpszModuleName, DWORD pID) {
    DWORD dwModuleBaseAddress = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pID); // make snapshot of all modules within process
    MODULEENTRY32 ModuleEntry32 = { 0 };
    ModuleEntry32.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(hSnapshot, &ModuleEntry32)) //store first Module in ModuleEntry32
    {
        do {
            if (_tcscmp(ModuleEntry32.szModule, lpszModuleName) == 0) // if Found Module matches Module we look for -> done!
            {
                dwModuleBaseAddress = (DWORD)ModuleEntry32.modBaseAddr;
                break;
            }
        } while (Module32Next(hSnapshot, &ModuleEntry32)); // go through Module entries in Snapshot and store in ModuleEntry32


    }
    CloseHandle(hSnapshot);
    return dwModuleBaseAddress;
}

DWORD GetPointerAddress(HWND hwnd, DWORD gameBaseAddr, DWORD address, vector<DWORD> offsets)
{
    DWORD pID = NULL; // Game process ID
    GetWindowThreadProcessId(hwnd, &pID);
    HANDLE phandle = NULL;
    phandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
    if (phandle == INVALID_HANDLE_VALUE || phandle == NULL);

    DWORD offset_null = NULL;
    ReadProcessMemory(phandle, (LPVOID*)(gameBaseAddr + address), &offset_null, sizeof(offset_null), 0);
    DWORD pointeraddress = offset_null; // the address we need
    for (int i = 0; i < offsets.size() - 1; i++) // we dont want to change the last offset value so we do -1
    {
        ReadProcessMemory(phandle, (LPVOID*)(pointeraddress + offsets.at(i)), &pointeraddress, sizeof(pointeraddress), 0);
    }
    return pointeraddress += offsets.at(offsets.size() - 1); // adding the last offset
}

DWORD pid;

int main()
{
    HWND hpvz = FindWindowA(0, "Plants vs. Zombies"); //Handle 2 win

    GetWindowThreadProcessId(hpvz, &pid);

    HANDLE pHandle = NULL;
    pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (pHandle == INVALID_HANDLE_VALUE || pHandle == NULL);

    char gamemodule1[] = "PlantsVsZombies.exe";
    DWORD gamebaseaddress1 = GetModuleBaseAddress(_T(gamemodule1), pid); //.exe module base address

    //Sun

    DWORD sunAddr = 0x00329670;
    vector<DWORD> sunOffsets{ 0x868, 0x5578 };
    DWORD sunPtrAddr = GetPointerAddress(hpvz, gamebaseaddress1, sunAddr, sunOffsets);

    //sun write mem

    int sun = 1337;
    int isSuccess = WriteProcessMemory(pHandle, (LPVOID*)(sunPtrAddr), &sun, 4,0);
    if (isSuccess > 0 )
    {
        cout << "Success." << endl;
    }
    else
    {
        cout << "Error.";
    }

    //cooldown write mem

    char bytes_cd[] = "\xFF\x47\x48";

    int cd_success = WriteProcessMemory(pHandle, (LPVOID)0x00491E4C, &bytes_cd, (DWORD)sizeof(bytes_cd), 0);
    if (cd_success > 0)
    {
        cout << "Success sunflower cooldown.";
    }
    else
    {
        cout << "CD sunflower error";
    }


    return 0;
}
