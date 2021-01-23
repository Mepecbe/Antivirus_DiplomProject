#include <ntifs.h>
#include <ntddk.h>
#include <ntdef.h>

#define PROCESS_VM_WRITE 0x0020
//extern "C" DRIVER_INITIALIZE DriverEntry;

/*
	for x64
*/

//=============================================================================
VOID GetImageNameFromProcess(_In_ PEPROCESS Target, _Out_ UCHAR* output) {
	DWORD64 ImageFilename = (DWORD64)Target + 0x2e0;
	RtlCopyMemory(output, (const void*)ImageFilename, 15);
}


//CALLBACKS
extern "C" void PostOperationCallback(
	PVOID RegistrationContext,
	POB_POST_OPERATION_INFORMATION OperationInformation
) {

	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(OperationInformation);
}

extern "C" OB_PREOP_CALLBACK_STATUS PreOperationCallback(
	PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION OperationInformation
) {
	UNREFERENCED_PARAMETER(RegistrationContext);

	PEPROCESS Target = (PEPROCESS)OperationInformation->Object;

	UCHAR imageName[15];
	GetImageNameFromProcess(Target, imageName);


	if (strcmp((const char*)imageName, "A_GUI.exe") != 0) {
		return OB_PREOP_SUCCESS;
	}


	if (OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE)
	{
		PEPROCESS _tmp = PsGetCurrentProcess();

		UCHAR tmpImagename[15];
		GetImageNameFromProcess(_tmp, tmpImagename);

		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[*] %s tried to violate the law!\n", tmpImagename);
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
	}

	return OB_PREOP_SUCCESS;
}


extern "C" NTSTATUS DriverEntry(
	struct _DRIVER_OBJECT* DriverObject,
	PUNICODE_STRING  RegistryPath
)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Start driver\nInit operation and registrator\n");

	OB_CALLBACK_REGISTRATION Registrator;
	OB_OPERATION_REGISTRATION Operation;

	Operation.ObjectType = PsProcessType;
	Operation.Operations = OB_OPERATION_HANDLE_CREATE;

	Operation.PostOperation = PostOperationCallback;
	Operation.PreOperation = PreOperationCallback;

	Registrator.Version = OB_FLT_REGISTRATION_VERSION;
	Registrator.OperationRegistrationCount = 1;
	RtlInitUnicodeString(&Registrator.Altitude, L"XXXXXXX");
	Registrator.OperationRegistration = &Operation;
	Registrator.RegistrationContext = nullptr;


	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "End init\n");


	HANDLE obHandle;
	NTSTATUS result = ObRegisterCallbacks(&Registrator, &obHandle);

	if (result == STATUS_SUCCESS) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "STATUS SUCCESS");
	}
	else {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "STATUS NOT SUCCESS, DEBUG PLS \n");
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%x", result);
	}

	return STATUS_SUCCESS;
}