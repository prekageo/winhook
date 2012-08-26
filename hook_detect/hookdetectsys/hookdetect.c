#include <ntddk.h>
#include <windef.h>

#include "../hookdetect/common.h"
#include "hookdetect.h"
#include "internals.h"

void UnloadDriver(PDRIVER_OBJECT DriverObject);
NTSTATUS DispatchCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DispatchIoctl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

typedef struct _DEVICE_EXTENSION {
    PDEVICE_OBJECT DeviceObject;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

PDEVICE_OBJECT g_pDeviceObject;
int g_win7;

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {
    NTSTATUS                  ntStatus;
    UNICODE_STRING            uszDriverString;
    UNICODE_STRING            uszDeviceString;
    UNICODE_STRING            uszProcessEventString;
    PDEVICE_OBJECT            pDeviceObject;
    PDEVICE_EXTENSION         extension;
    HANDLE                    hProcessHandle;
    RTL_OSVERSIONINFOW version;

    RtlInitUnicodeString(&uszDriverString, L"\\Device\\hookdetect");
    ntStatus = IoCreateDevice(DriverObject,sizeof(DEVICE_EXTENSION),&uszDriverString,FILE_DEVICE_UNKNOWN,0,FALSE,&pDeviceObject);
    if(ntStatus != STATUS_SUCCESS)
        return ntStatus;
    extension = pDeviceObject->DeviceExtension;
    RtlInitUnicodeString(&uszDeviceString, L"\\DosDevices\\hookdetect");
    ntStatus = IoCreateSymbolicLink(&uszDeviceString, &uszDriverString);

    if(ntStatus != STATUS_SUCCESS){
        IoDeleteDevice(pDeviceObject);
        return ntStatus;
    }
    g_pDeviceObject = pDeviceObject;
    DriverObject->DriverUnload                         = UnloadDriver;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

    version.dwOSVersionInfoSize = sizeof(version);
    RtlGetVersion(&version);
    if (((version.dwMajorVersion << 8) | version.dwMinorVersion) >= 0x0601) {
        g_win7 = 1;
    } else {
        g_win7 = 0;
    }

    return ntStatus;
}

NTSTATUS DispatchCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp){
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

UserGetAtomName_ptr UserGetAtomName;
ATOM *aatomSysLoaded;

int has_hooks(PHOOK *aphkStart) {
    unsigned int i;

    for (i=0;i<NB_HOOKS;i++) {
        if (aphkStart[i]) {
            return 1;
        }
    }
    return 0;
}

void retrieve_hooks(PHOOK *aphkStart, PPROCESSINFO ppi, hook *hook) {
    unsigned int i, j;
    PHOOK phook, phook_next;

    for (i=0;i<NB_HOOKS;i++) {
        phook = aphkStart[i];
        hook[i].handlers = 0;
        if (phook) {
            phook_next = phook;
            do {
                hook[i].handlers++;
            } while (phook_next = phook_next->next_address);
            for(j=0;j<min(MAX_HANDLERS, hook[i].handlers);j++) {
                hook[i].handler[j].internal_stuff.unknown_0 = phook->unknown_0;
                hook[i].handler[j].internal_stuff.unknown_4 = phook->unknown_4;
                hook[i].handler[j].internal_stuff.unknown_8 = phook->unknown_8;
                hook[i].handler[j].internal_stuff.unknown_C = phook->unknown_C;
                hook[i].handler[j].internal_stuff.self_address = (DWORD)phook->self_address;
                hook[i].handler[j].internal_stuff.next_address = (DWORD)phook->next_address;
                hook[i].handler[j].internal_stuff.hook_type = phook->hook_type;
                hook[i].handler[j].proc_relative_offset = phook->proc_relative_offset;
                hook[i].handler[j].internal_stuff.flags = phook->flags;
                hook[i].handler[j].hmod_table_index = phook->hmod_table_index;
                hook[i].handler[j].internal_stuff.thread_id = phook->thread_id;

                if (phook->hmod_table_index >= 0) {
                    if (g_win7) {
                        hook[i].handler[j].module_base = ((DWORD*)ppi)[0xC0/4+phook->hmod_table_index];
                    } else {
                        hook[i].handler[j].module_base = (DWORD)ppi->ahmodLibLoaded[phook->hmod_table_index];
                    }
                }
                phook = phook->next_address;
            }
        }
    }
}

NTSTATUS DispatchIoctl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp){
    NTSTATUS  ntStatus = STATUS_UNSUCCESSFUL;
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    PDEVICE_EXTENSION extension = DeviceObject->DeviceExtension;
    switch(irpStack->Parameters.DeviceIoControl.IoControlCode){
        case IOCTL_GET_HOOKS:
            {
                unsigned int i,j;
                PETHREAD pethread;
                PTHREADINFO ptiCurrent;
                PDESKTOPINFO pdesktopinfo;
                PPROCESSINFO ppi;
                PARAMS_GET_HOOKS *params;
                DATA_GET_HOOKS *data;
                PHOOK* aphkStart;

                if (irpStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(DATA_GET_HOOKS)) {
                    ntStatus = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                if (irpStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(PARAMS_GET_HOOKS)) {
                    ntStatus = STATUS_BUFFER_TOO_SMALL;
                    break;
                }

                params = ExAllocatePoolWithTag(PagedPool, sizeof(PARAMS_GET_HOOKS), 'tdkh');
                if (!params) {
                    break;
                }

                memcpy(params, Irp->AssociatedIrp.SystemBuffer, sizeof(PARAMS_GET_HOOKS));

                pethread = PsGetCurrentThread();
                ptiCurrent = PsGetThreadWin32Thread(pethread);
                if (g_win7) {
                    pdesktopinfo = (PDESKTOPINFO)((unsigned int*)ptiCurrent)[0xCC/4];
                    ppi = (PPROCESSINFO)&((char*)ptiCurrent)[0xB8];
                    aphkStart = (PHOOK*)&((char*)pdesktopinfo)[0x10];
                } else {
                    pdesktopinfo = ptiCurrent->pDeskInfo;
                    ppi = ptiCurrent->ppi;
                    aphkStart = pdesktopinfo->aphkStart;
                }

                data = (DATA_GET_HOOKS*)Irp->AssociatedIrp.SystemBuffer;
                memset(data, 0, sizeof(DATA_GET_HOOKS));

                retrieve_hooks(aphkStart, ppi, data->global_hook);

                data->threads=0;
                j=0;
                for (i=0;i<params->threads;i++) {
                    if (PsLookupThreadByThreadId((HANDLE)params->thread_id[i], &pethread) != STATUS_SUCCESS) {
                        continue;
                    }
                    if (g_win7) {
                        if (PsGetThreadSessionId(pethread) != PsGetCurrentProcessSessionId()) {
                            ObDereferenceObject(pethread);
                            continue;
                        }
                    }
                    ptiCurrent = PsGetThreadWin32Thread(pethread);
                    if (ptiCurrent) {
                        if (g_win7) {
                            aphkStart = (PHOOK*)&((char*)ptiCurrent)[0x198];
                            ppi = (PPROCESSINFO)&((char*)ptiCurrent)[0xB8];
                        } else {
                            aphkStart = (PHOOK*)&((char*)ptiCurrent)[0xf4];
                            ppi = ptiCurrent->ppi;
                        }
                        if (has_hooks(aphkStart)) {
                            data->threads++;
                            if (j<MAX_OUT_THREADS) {
                                retrieve_hooks(aphkStart, ppi, data->thread[j].hook);
                                data->thread[j].thread_id = params->thread_id[i];
                                j++;
                            }
                        }
                    }
                    ObDereferenceObject(pethread);
                }

                ExFreePool(params);

                ntStatus = STATUS_SUCCESS;
                break;
            }
        case IOCTL_HMOD_TBL_INX_TO_MOD_NAME:
            {
                DATA_HMOD_TBL_INX_TO_MOD_NAME *data;
                PARAMS_HMOD_TBL_INX_TO_MOD_NAME *params;
                WCHAR tmp;
                int hmod_table_index;

                if (irpStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(DATA_HMOD_TBL_INX_TO_MOD_NAME)) {
                    ntStatus = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                if (irpStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(PARAMS_HMOD_TBL_INX_TO_MOD_NAME)) {
                    ntStatus = STATUS_BUFFER_TOO_SMALL;
                    break;
                }

                params = Irp->AssociatedIrp.SystemBuffer;

                UserGetAtomName = (UserGetAtomName_ptr)params->UserGetAtomName_address;
                aatomSysLoaded = (ATOM*)params->aatomSysLoaded_address;
                hmod_table_index = params->hmod_table_index;

                if (UserGetAtomName && aatomSysLoaded) {
                    __try {
                        (*UserGetAtomName)(aatomSysLoaded[0], &tmp, 1);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        UserGetAtomName = 0;
                    }
                }

                data = Irp->AssociatedIrp.SystemBuffer;

                if (UserGetAtomName) {
                    (*UserGetAtomName)(aatomSysLoaded[hmod_table_index], data->module_name, MAX_PATH);
                } else {
                    data->module_name[0] = 0;
                }

                ntStatus = STATUS_SUCCESS;
                break;
            }
    }

    Irp->IoStatus.Status = ntStatus;
    if(ntStatus == STATUS_SUCCESS)
        Irp->IoStatus.Information = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
    else
        Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return ntStatus;
}

void UnloadDriver(IN PDRIVER_OBJECT DriverObject){
    UNICODE_STRING  uszDeviceString;
    NTSTATUS        ntStatus = STATUS_DEVICE_CONFIGURATION_ERROR;
    IoDeleteDevice(DriverObject->DeviceObject);
    RtlInitUnicodeString(&uszDeviceString, L"\\DosDevices\\hookdetect");
    IoDeleteSymbolicLink(&uszDeviceString);
}
