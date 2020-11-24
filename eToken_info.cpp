#include "stdlib.h"
#include "stdio.h"
#include <windows.h>
#include "include\eTPkcs11.h"

using namespace std;

void init();
void leave(const char*);
void displayLibraryInfo();
void displayTokenInfo(DWORD slotId);

//Глобальные переменные
CK_FUNCTION_LIST_PTR pFunctionList=NULL;
CK_C_GetFunctionList pGFL = 0;
bool wasInit = false;
static HANDLE hThread = 0;

static DWORD __stdcall TokenNotifyThread(void*)
{
while (true)
{
DWORD slotId;
int res = pFunctionList->C_WaitForSlotEvent(0, &slotId, 0);

if (res==CKR_OK) displayTokenInfo(slotId);
 else break;
}
return 0;
}

int main()
{
	init();
    displayLibraryInfo();
	hThread = CreateThread(NULL, 0, TokenNotifyThread, NULL, 0, NULL);
	displayTokenInfo(8);
	getchar();
    return 0;
}

void init()
{
 // Загружаем dll
 HINSTANCE hLib = LoadLibraryA("etpkcs11.DLL");
 if (hLib == NULL)
 {
 leave ("Cannot load DLL.");
 }

 // Ищем точку входа для C_GetFunctionList
 (FARPROC&)pGFL= GetProcAddress(hLib, "C_GetFunctionList");
 if (pGFL == NULL)
 {
 leave ("Cannot find GetFunctionList().");
 }
 //Берем список функций
 if (CKR_OK != pGFL(&pFunctionList))
 {
 leave ("Can't get function list. \n");
 }
 // Инициализируем библиотеку PKCS#11

 if (CKR_OK != pFunctionList->C_Initialize (0))
 {
 leave ("C_Initialize failed...\n");
 }
 wasInit = true;
}

static void leave(const char * message)
{
 if (message) printf("%s ", message);
if(wasInit)
 {
// Закрываем библиотеку PKCS#11
if (CKR_OK != pFunctionList->C_Finalize(0))
{
printf ("C_Finalize failed...\n");
}
//ждем завершения работы потока, иначе убиваем его.
WaitForSingleObject(hThread, 5000);
if (hThread) { TerminateThread(hThread,0); CloseHandle(hThread); }
 hThread = 0;
 wasInit = false;
 }
exit(message ? -1 : 0 );
}

void displayLibraryInfo()
{
	CK_INFO info;
	CK_RV tmp = CKR_OK;
	tmp = pFunctionList->C_GetInfo(&info);
	if (CKR_OK != tmp)
	{
		printf("Error: C_GetInfo failed...\n");
		return;
	}
	printf("version: %d.%d\n", info.cryptokiVersion.major, info.cryptokiVersion.minor);
	printf("manufacturer id: %s\n", info.manufacturerID);
	printf("library description: %s\n", info.libraryDescription);
	printf("library version: %d.%d\n", info.libraryVersion.major, info.libraryVersion.minor);
}

void displayTokenInfo(DWORD slotId)
{
	CK_SLOT_INFO slot_info;
	CK_RV tmp = CKR_OK;
	tmp = pFunctionList->C_GetSlotInfo(slotId, &slot_info);
	if (CKR_OK != tmp)
	{
		printf("Error: C_GetSlotInfo failed...\n");
		return;
	}
	printf("slot description: %s\n", slot_info.slotDescription);
	if (!(slot_info.flags & CKF_TOKEN_PRESENT))
	{
		printf("eToken was not find.\n");
		return;
	}
	CK_TOKEN_INFO token_info;
	tmp = pFunctionList->C_GetTokenInfo(slotId, &token_info);
	if (CKR_OK != tmp)
	{
		printf("Error: C_GetTokenInfo failed...\n");
		return;
	}
	printf("manufacturer: %s\n", token_info.manufacturerID);
	printf("model: %s\n", token_info.model);
	printf("serialNumber: %d\n", token_info.serialNumber);
	printf("ulRwSessionCount: %d\n", token_info.ulRwSessionCount);
	printf("ulTotalPrivateMemory: %d\n", token_info.ulTotalPrivateMemory);
	printf("ulFreePrivateMemory: %d\n", token_info.ulFreePrivateMemory);
	if (token_info.flags & CKF_WRITE_PROTECTED)
		 printf("eToken is write protected.\n");
	else printf("eToken not write protected.\n");
	if (token_info.flags & CKF_USER_PIN_INITIALIZED)
		printf("custom Pin set.\n");
	else printf("no custom Pin set.\n");
}


