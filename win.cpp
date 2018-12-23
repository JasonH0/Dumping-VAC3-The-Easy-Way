std::string GetFilePath()
{
    char szBuffer[MAX_PATH] = {NULL};
    GetModuleFileNameA(hModule, szBuffer, MAX_PATH);

    std::string szPath(szBuffer);

    return szPath.substr(0, szPath.find_last_of('\\') + 1);
}

std::string GetSystemTimeString()
{
    SYSTEMTIME sysTime;
    ZeroMemory(&sysTime, sizeof(sysTime));

    GetSystemTime(&sysTime);

    char szTime[MAX_PATH] = {NULL};
    sprintf(szTime, "-%i-%i-%i", sysTime.wMonth, sysTime.wDay, sysTime.wYear);

    return szTime;
}

std::string GetBinaryString(std::string szFile)
{
    std::string szPath = GetFilePath();
    std::string szTime = GetSystemTimeString();

    szPath.append(szFile);
    szPath.append(szTime);
    szPath.append(".dll");

    return szPath;
}

void DumpVAC3(PVOID pBase, DWORD dwSize)
{
    std::ofstream VAC3File(GetBinaryString("VAC3"), std::ios::binary);
    VAC3File.write((char*)pBase, dwSize);
    VAC3File.close();
}

LONG WINAPI hExceptionFilter(_EXCEPTION_POINTERS* ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT)
    {
        // Whoo, we hit that VAC3 shit so let's grab some data
        DWORD dwESI = ExceptionInfo->ContextRecord->Esi;
        DWORD dwSize = *(DWORD*)(dwESI + 0x14);
        PVOID pVAC3 = *(PVOID*)(dwESI + 0x18);

        // Take a DUMP
        DumpVAC3(pVAC3, dwSize);

        // Time to peace out as sloppy as we possibly can
        ExitProcess(-1);
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

VOID SetupException()
{
    DWORD dwCmp = SteamServiceFindPattern("\x83\x7E\x04\x00\x74\x18", "xxxxxx");
    DWORD dwProtection = NULL;
    VirtualProtect((PVOID)dwCmp, 0x1, PAGE_EXECUTE_READWRITE, &dwProtection);
    *(BYTE*)(dwCmp) = 0xCC;
    VirtualProtect((PVOID)dwCmp, 0x1, dwProtection, NULL);
    AddVectoredExceptionHandler(1, hExceptionFilter);
}