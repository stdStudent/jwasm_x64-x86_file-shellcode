#include <stdio.h>
#include <windows.h>
#include <tchar.h>
#pragma warning (disable: 4996)

typedef void (*FileFunc)(TCHAR*); // Define a function pointer type

void searchForFiles(TCHAR* szDir, TCHAR* fileExtension, FileFunc func)
{
    WIN32_FIND_DATA ffd;
    TCHAR szExt[_MAX_EXT];
    _stprintf(szExt, _T("\\*%s"), fileExtension);
    _tcscat(szDir, szExt);
    HANDLE hFind = FindFirstFile(szDir, &ffd);

    do
    {
        if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            func(ffd.cFileName);
        }
    } while (FindNextFile(hFind, &ffd) != 0);
    FindClose(hFind);
}

void printFileName(TCHAR* fileName)
{
    _tprintf(TEXT("%s\n"), fileName);
}

int main()
{
    TCHAR szDir[260] = {0}; // Allocate a larger buffer
    _tcscpy(szDir, _T("C:\\Users\\Labour\\Downloads"));
    searchForFiles(szDir, _T(".exe"), printFileName);
    return 0;
}
