// dllmain.cpp : DLL アプリケーションのエントリ ポイントを定義します。
#include "pch.h"
#include "windows.h"
#include "winternl.h"
#include <stdio.h>
#include "stdlib.h"
#include "ntstatus.h"

#ifndef __kernel_long_t
typedef long		__kernel_long_t;
typedef unsigned long	__kernel_ulong_t;
#endif

#ifndef __kernel_ino_t
typedef __kernel_ulong_t __kernel_ino_t;
#endif

#ifndef __kernel_mode_t
typedef unsigned int	__kernel_mode_t;
#endif

#ifndef __kernel_pid_t
typedef int		__kernel_pid_t;
#endif

#ifndef __kernel_ipc_pid_t
typedef int		__kernel_ipc_pid_t;
#endif

#ifndef __kernel_uid_t
typedef unsigned int	__kernel_uid_t;
typedef unsigned int	__kernel_gid_t;
#endif

#ifndef __kernel_suseconds_t
typedef __kernel_long_t		__kernel_suseconds_t;
#endif

#ifndef __kernel_daddr_t
typedef int		__kernel_daddr_t;
#endif

#ifndef __kernel_uid32_t
typedef unsigned int	__kernel_uid32_t;
typedef unsigned int	__kernel_gid32_t;
#endif

#ifndef __kernel_old_uid_t
typedef __kernel_uid_t	__kernel_old_uid_t;
typedef __kernel_gid_t	__kernel_old_gid_t;
#endif

#ifndef __kernel_old_dev_t
typedef unsigned int	__kernel_old_dev_t;
#endif

typedef __kernel_long_t	__kernel_off_t;
typedef long long	__kernel_loff_t;
typedef __kernel_long_t	__kernel_old_time_t;

#define __u8 UINT8
#define __u16 UINT16
#define __u32 UINT32
#define __u64 UINT64
#define __s8 INT8
#define __s16 INT16
#define __s32 INT32
#define __s64 INT64

struct __uint128_t { UINT64 q[2]; };

#include "ioctl.h"
#include "fcntl.h"
#include "ptrace_arm64.h"
#include "kvm_arm64.h"
#include "kvm.h"
#include "mman.h"

#pragma warning(disable:4996)

/*
mov x8,#56
mov x3,x2
mov x2,x1
mov x1,x0
mov x0,#-100
svc #0
ret
*/
char open_inst_data[] = { 0x08,0x07,0x80,0xD2,0xE3,0x03,0x02,0xAA,0xE2,0x03,0x01,0xAA,0xE1,0x03,0x00,0xAA,0x60,0x0C,0x80,0x92,0x01,0x00,0x00,0xD4,0xC0,0x03,0x5F,0xD6 };
int (*open)(const char*, int, int) = ((int (*)(const char*, int, int)) & open_inst_data);
/*
mov x8,#29
svc #0
ret
*/
char ioctl_inst_data[] = { 0xA8,0x03,0x80,0xD2,0x01,0x00,0x00,0xD4,0xC0,0x03,0x5F,0xD6 };
int (*ioctl)(unsigned int, unsigned int, unsigned int) = ((int (*)(unsigned int, unsigned int, unsigned int)) & ioctl_inst_data);
/*
mov x8,#222
svc #0
ret
*/
char mmap_inst_data[] = { 0xC8,0x1B,0x80,0xD2,0x01,0x00,0x00,0xD4,0xC0,0x03,0x5F,0xD6 };
int (*mmap)(void*, size_t, int, int, int, unsigned int) = ((int (*)(void*, size_t, int, int, int, unsigned int)) & mmap_inst_data);


extern char modulename4this[4096];
typedef NTSYSAPI NTSTATUS  WINAPI t_LdrLoadDll(LPCWSTR, DWORD, const UNICODE_STRING*, HMODULE*);
t_LdrLoadDll* LdrLoadDll = 0;

typedef struct
{
	ULONG   version;
	ULONG   unknown1[3];
	ULONG64 unknown2;
	ULONG64 pLdrInitializeThunk;
	ULONG64 pKiUserExceptionDispatcher;
	ULONG64 pKiUserApcDispatcher;
	ULONG64 pKiUserCallbackDispatcher;
	ULONG64 pRtlUserThreadStart;
	ULONG64 pRtlpQueryProcessDebugInformationRemote;
	ULONG64 ntdll_handle;
	ULONG64 pLdrSystemDllInitBlock;
	ULONG64 pRtlpFreezeTimeBias;
} SYSTEM_DLL_INIT_BLOCK;

SYSTEM_DLL_INIT_BLOCK* pLdrSystemDllInitBlock = NULL;

typedef NTSYSAPI PVOID t_RtlAllocateHeap(PVOID, ULONG, SIZE_T);
t_RtlAllocateHeap* RtlAllocateHeap = 0;
typedef NTSYSCALLAPI NTSTATUS t_NtSetInformationThread(HANDLE, THREADINFOCLASS, PVOID, ULONG);
t_NtSetInformationThread* NtSetInformationThread_alternative = 0;
typedef NTSTATUS WINAPI t_RtlWow64GetCurrentCpuArea(USHORT, void**, void**);
t_RtlWow64GetCurrentCpuArea* RtlWow64GetCurrentCpuArea = 0;
typedef __kernel_entry NTSTATUS t_NtQueryInformationThread(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
t_NtQueryInformationThread* NtQueryInformationThread_alternative = 0;

typedef NTSTATUS WINAPI t_Wow64SystemServiceEx(UINT, UINT*);
t_Wow64SystemServiceEx* Wow64SystemServiceEx = 0;

HMODULE hmhm4dll;

char modulename4this[4096];

typedef NTSYSAPI NTSTATUS  WINAPI t_LdrDisableThreadCalloutsForDll(HMODULE);
t_LdrDisableThreadCalloutsForDll* LdrDisableThreadCalloutsForDll;

static NTSTATUS(WINAPI* p__wine_unix_call)(UINT64, unsigned int, void*);
typedef NTSTATUS WINAPI t__wine_unix_call(UINT64, unsigned int, void*);

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	HMODULE hofntdll = 0;
	HMODULE HM = 0;
	HMODULE HM2 = 0;
	HMODULE HMHM = 0;
	DWORD Tmp;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		GetModuleFileNameA(hModule, modulename4this, sizeof(modulename4this));
		hmhm4dll = hModule;
		hofntdll = LoadLibraryA("C:\\Windows\\System32\\ntdll.dll");
		if (hofntdll == 0) { return false; }
		LdrLoadDll = (t_LdrLoadDll*)GetProcAddress(hofntdll, "LdrLoadDll");
		LdrDisableThreadCalloutsForDll = (t_LdrDisableThreadCalloutsForDll*)GetProcAddress(hofntdll, "LdrDisableThreadCalloutsForDll");
		if (LdrDisableThreadCalloutsForDll == 0) { return false; }
		RtlAllocateHeap = (t_RtlAllocateHeap*)GetProcAddress(hofntdll, "RtlAllocateHeap");
		NtSetInformationThread_alternative = (t_NtSetInformationThread*)GetProcAddress(hofntdll, "NtSetInformationThread");
		NtQueryInformationThread_alternative = (t_NtQueryInformationThread*)GetProcAddress(hofntdll, "NtQueryInformationThread");
		RtlWow64GetCurrentCpuArea = (t_RtlWow64GetCurrentCpuArea*)GetProcAddress(hofntdll, "RtlWow64GetCurrentCpuArea");
		LdrDisableThreadCalloutsForDll(hModule);
		pLdrSystemDllInitBlock = (SYSTEM_DLL_INIT_BLOCK*)GetProcAddress(hofntdll, "LdrSystemDllInitBlock");
		if (pLdrSystemDllInitBlock != 0) {
			if (pLdrSystemDllInitBlock->ntdll_handle == 0) { pLdrSystemDllInitBlock->ntdll_handle = (ULONG64)hofntdll; }
		}
		HM2 = LoadLibraryA("C:\\Windows\\Sysnative\\Wow64.dll");
		if (HM2 == 0) { HM2 = LoadLibraryA("C:\\Windows\\System32\\Wow64.dll"); }
		if (HM2 == 0) { return false; }
		Wow64SystemServiceEx = (t_Wow64SystemServiceEx*)GetProcAddress(HM2, "Wow64SystemServiceEx");
		if (!p__wine_unix_call) {
			p__wine_unix_call = (t__wine_unix_call*)GetProcAddress(hofntdll, "__wine_unix_call");
		}
		VirtualProtect(ioctl_inst_data, sizeof(ioctl_inst_data), PAGE_EXECUTE_READWRITE, &Tmp);
        VirtualProtect(open_inst_data, sizeof(open_inst_data), PAGE_EXECUTE_READWRITE, &Tmp);
		VirtualProtect(mmap_inst_data, sizeof(mmap_inst_data), PAGE_EXECUTE_READWRITE, &Tmp);
		FlushInstructionCache(GetCurrentProcess(), ioctl_inst_data, sizeof(ioctl_inst_data));
        FlushInstructionCache(GetCurrentProcess(), open_inst_data, sizeof(open_inst_data));
		FlushInstructionCache(GetCurrentProcess(), mmap_inst_data, sizeof(mmap_inst_data));
	case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

#if 0
typedef struct DECLSPEC_ALIGN(16) _M128A {
	ULONGLONG Low;
	LONGLONG High;
} M128A, * PM128A;

typedef struct _XSAVE_FORMAT {
	WORD ControlWord;        /* 000 */
	WORD StatusWord;         /* 002 */
	BYTE TagWord;            /* 004 */
	BYTE Reserved1;          /* 005 */
	WORD ErrorOpcode;        /* 006 */
	DWORD ErrorOffset;       /* 008 */
	WORD ErrorSelector;      /* 00c */
	WORD Reserved2;          /* 00e */
	DWORD DataOffset;        /* 010 */
	WORD DataSelector;       /* 014 */
	WORD Reserved3;          /* 016 */
	DWORD MxCsr;             /* 018 */
	DWORD MxCsr_Mask;        /* 01c */
	M128A FloatRegisters[8]; /* 020 */
	M128A XmmRegisters[16];  /* 0a0 */
	BYTE Reserved4[96];      /* 1a0 */
} XSAVE_FORMAT, * PXSAVE_FORMAT;
#endif


struct I386_FLOATING_SAVE_AREA {
	DWORD ControlWord;
	DWORD StatusWord;
	DWORD TagWord;
	DWORD ErrorOffset;
	DWORD ErrorSelector;
	DWORD DataOffset;
	DWORD DataSelector;
	BYTE RegisterArea[80];
	DWORD Cr0NpxState;
};

struct I386_CONTEXT {
	DWORD ContextFlags;

	DWORD Dr0;
	DWORD Dr1;
	DWORD Dr2;
	DWORD Dr3;
	DWORD Dr6;
	DWORD Dr7;

	I386_FLOATING_SAVE_AREA FloatSave;

	DWORD SegGs;
	DWORD SegFs;
	DWORD SegEs;
	DWORD SegDs;

	DWORD Edi;
	DWORD Esi;
	DWORD Ebx;
	DWORD Edx;
	DWORD Ecx;
	DWORD Eax;

	DWORD Ebp;
	DWORD Eip;
	DWORD SegCs;
	DWORD EFlags;
	DWORD Esp;
	DWORD SegSs;

	BYTE ExtendedRegisters[512];
};

#define CONTEXT_EXCEPTION_ACTIVE    0x08000000
#define CONTEXT_SERVICE_ACTIVE      0x10000000
#define CONTEXT_EXCEPTION_REQUEST   0x40000000
#define CONTEXT_EXCEPTION_REPORTING 0x80000000

#define CONTEXT_ARM    0x0200000
#define CONTEXT_ARM_CONTROL         (CONTEXT_ARM | 0x00000001)
#define CONTEXT_ARM_INTEGER         (CONTEXT_ARM | 0x00000002)
#define CONTEXT_ARM_FLOATING_POINT  (CONTEXT_ARM | 0x00000004)
#define CONTEXT_ARM_DEBUG_REGISTERS (CONTEXT_ARM | 0x00000008)
#define CONTEXT_ARM_FULL (CONTEXT_ARM_CONTROL | CONTEXT_ARM_INTEGER)
#define CONTEXT_ARM_ALL  (CONTEXT_ARM_FULL | CONTEXT_ARM_FLOATING_POINT | CONTEXT_ARM_DEBUG_REGISTERS)

#define ARM_MAX_BREAKPOINTS     8
#define ARM_MAX_WATCHPOINTS     1

typedef struct _IMAGE_ARM_RUNTIME_FUNCTION
{
	DWORD BeginAddress;
	union {
		DWORD UnwindData;
		struct {
			DWORD Flag : 2;
			DWORD FunctionLength : 11;
			DWORD Ret : 2;
			DWORD H : 1;
			DWORD Reg : 3;
			DWORD R : 1;
			DWORD L : 1;
			DWORD C : 1;
			DWORD StackAdjust : 10;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;
} IMAGE_ARM_RUNTIME_FUNCTION_ENTRY, * PIMAGE_ARM_RUNTIME_FUNCTION_ENTRY;

typedef struct _SCOPE_TABLE_ARM
{
	DWORD Count;
	struct
	{
		DWORD BeginAddress;
		DWORD EndAddress;
		DWORD HandlerAddress;
		DWORD JumpTarget;
	} ScopeRecord[1];
} SCOPE_TABLE_ARM, * PSCOPE_TABLE_ARM;

typedef struct _ARM_NEON128
{
	ULONGLONG Low;
	LONGLONG High;
} ARM_NEON128;

typedef struct _ARM_CONTEXT
{
	ULONG ContextFlags;             /* 000 */
	/* CONTEXT_INTEGER */
	ULONG R0;                       /* 004 */
	ULONG R1;                       /* 008 */
	ULONG R2;                       /* 00c */
	ULONG R3;                       /* 010 */
	ULONG R4;                       /* 014 */
	ULONG R5;                       /* 018 */
	ULONG R6;                       /* 01c */
	ULONG R7;                       /* 020 */
	ULONG R8;                       /* 024 */
	ULONG R9;                       /* 028 */
	ULONG R10;                      /* 02c */
	ULONG R11;                      /* 030 */
	ULONG R12;                      /* 034 */
	/* CONTEXT_CONTROL */
	ULONG Sp;                       /* 038 */
	ULONG Lr;                       /* 03c */
	ULONG Pc;                       /* 040 */
	ULONG Cpsr;                     /* 044 */
	/* CONTEXT_FLOATING_POINT */
	ULONG Fpscr;                    /* 048 */
	ULONG Padding;                  /* 04c */
	union
	{
		ARM_NEON128 Q[16];
		ULONGLONG D[32];
		ULONG S[32];
	} DUMMYUNIONNAME;               /* 050 */
	/* CONTEXT_DEBUG_REGISTERS */
	ULONG Bvr[ARM_MAX_BREAKPOINTS]; /* 150 */
	ULONG Bcr[ARM_MAX_BREAKPOINTS]; /* 170 */
	ULONG Wvr[ARM_MAX_WATCHPOINTS]; /* 190 */
	ULONG Wcr[ARM_MAX_WATCHPOINTS]; /* 194 */
	ULONG Padding2[2];              /* 198 */
} ARM_CONTEXT;

char bopcode[] = { 0xE0,0xF7,0x01,0x80,0xf7,0x46 };
char unixbopcode[] = { 0xE0,0xF7,0x02,0x80,0xf7,0x46 };
#ifndef ThreadWow64Context
#define ThreadWow64Context (THREADINFOCLASS)0x1d
#endif

#ifndef STATUS_INVALID_ADDRESS
#define STATUS_INVALID_ADDRESS -1073741503
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0
#endif

typedef struct _GDI_TEB_BATCH
{
	ULONG  Offset;
	HANDLE HDC;
	ULONG  Buffer[0x136];
} GDI_TEB_BATCH;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
	struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
	struct _ACTIVATION_CONTEXT* ActivationContext;
	ULONG                                       Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK
{
	RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
	LIST_ENTRY                          FrameListCache;
	ULONG                               Flags;
	ULONG                               NextCookieSequenceNumber;
	ULONG_PTR                           StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
	ULONG       Flags;
	const char* FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT_EX
{
	TEB_ACTIVE_FRAME_CONTEXT BasicContext;
	const char* SourceLocation;
} TEB_ACTIVE_FRAME_CONTEXT_EX, * PTEB_ACTIVE_FRAME_CONTEXT_EX;

typedef struct _TEB_ACTIVE_FRAME
{
	ULONG                     Flags;
	struct _TEB_ACTIVE_FRAME* Previous;
	TEB_ACTIVE_FRAME_CONTEXT* Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

typedef struct _TEB_ACTIVE_FRAME_EX
{
	TEB_ACTIVE_FRAME BasicFrame;
	void* ExtensionIdentifier;
} TEB_ACTIVE_FRAME_EX, * PTEB_ACTIVE_FRAME_EX;

typedef struct _TEB_FLS_DATA
{
	LIST_ENTRY      fls_list_entry;
	void** fls_data_chunks[8];
} TEB_FLS_DATA, * PTEB_FLS_DATA;

typedef struct ___TEB
{                                                                 /* win32/win64 */
	NT_TIB                       Tib;                               /* 000/0000 */
	PVOID                        EnvironmentPointer;                /* 01c/0038 */
	CLIENT_ID                    ClientId;                          /* 020/0040 */
	PVOID                        ActiveRpcHandle;                   /* 028/0050 */
	PVOID                        ThreadLocalStoragePointer;         /* 02c/0058 */
	PPEB                         Peb;                               /* 030/0060 */
	ULONG                        LastErrorValue;                    /* 034/0068 */
	ULONG                        CountOfOwnedCriticalSections;      /* 038/006c */
	PVOID                        CsrClientThread;                   /* 03c/0070 */
	PVOID                        Win32ThreadInfo;                   /* 040/0078 */
	ULONG                        User32Reserved[26];                /* 044/0080 */
	ULONG                        UserReserved[5];                   /* 0ac/00e8 */
	PVOID                        WOW32Reserved;                     /* 0c0/0100 */
	ULONG                        CurrentLocale;                     /* 0c4/0108 */
	ULONG                        FpSoftwareStatusRegister;          /* 0c8/010c */
	PVOID                        ReservedForDebuggerInstrumentation[16]; /* 0cc/0110 */
#ifdef _WIN64
	PVOID                        SystemReserved1[30];               /*    /0190 */
#else
	PVOID                        SystemReserved1[26];               /* 10c/     used for krnl386 private data in Wine */
#endif
	char                         PlaceholderCompatibilityMode;      /* 174/0280 */
	char                         PlaceholderReserved[11];           /* 175/0281 */
	DWORD                        ProxiedProcessId;                  /* 180/028c */
	ACTIVATION_CONTEXT_STACK     ActivationContextStack;            /* 184/0290 */
	UCHAR                        WorkingOnBehalfOfTicket[8];        /* 19c/02b8 */
	LONG                         ExceptionCode;                     /* 1a4/02c0 */
	ACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;     /* 1a8/02c8 */
	ULONG_PTR                    InstrumentationCallbackSp;         /* 1ac/02d0 */
	ULONG_PTR                    InstrumentationCallbackPreviousPc; /* 1b0/02d8 */
	ULONG_PTR                    InstrumentationCallbackPreviousSp; /* 1b4/02e0 */
#ifdef _WIN64
	ULONG                        TxFsContext;                       /*    /02e8 */
	BOOLEAN                      InstrumentationCallbackDisabled;   /*    /02ec */
#else
	BOOLEAN                      InstrumentationCallbackDisabled;   /* 1b8/     */
	BYTE                         SpareBytes1[23];                   /* 1b9/     */
	ULONG                        TxFsContext;                       /* 1d0/     */
#endif
	GDI_TEB_BATCH                GdiTebBatch;                       /* 1d4/02f0 used for ntdll private data in Wine */
	CLIENT_ID                    RealClientId;                      /* 6b4/07d8 */
	HANDLE                       GdiCachedProcessHandle;            /* 6bc/07e8 */
	ULONG                        GdiClientPID;                      /* 6c0/07f0 */
	ULONG                        GdiClientTID;                      /* 6c4/07f4 */
	PVOID                        GdiThreadLocaleInfo;               /* 6c8/07f8 */
	ULONG_PTR                    Win32ClientInfo[62];               /* 6cc/0800 used for user32 private data in Wine */
	PVOID                        glDispatchTable[233];              /* 7c4/09f0 */
	PVOID                        glReserved1[29];                   /* b68/1138 */
	PVOID                        glReserved2;                       /* bdc/1220 */
	PVOID                        glSectionInfo;                     /* be0/1228 */
	PVOID                        glSection;                         /* be4/1230 */
	PVOID                        glTable;                           /* be8/1238 */
	PVOID                        glCurrentRC;                       /* bec/1240 */
	PVOID                        glContext;                         /* bf0/1248 */
	ULONG                        LastStatusValue;                   /* bf4/1250 */
	UNICODE_STRING               StaticUnicodeString;               /* bf8/1258 */
	WCHAR                        StaticUnicodeBuffer[261];          /* c00/1268 */
	PVOID                        DeallocationStack;                 /* e0c/1478 */
	PVOID                        TlsSlots[64];                      /* e10/1480 */
	LIST_ENTRY                   TlsLinks;                          /* f10/1680 */
	PVOID                        Vdm;                               /* f18/1690 */
	PVOID                        ReservedForNtRpc;                  /* f1c/1698 */
	PVOID                        DbgSsReserved[2];                  /* f20/16a0 */
	ULONG                        HardErrorDisabled;                 /* f28/16b0 */
	PVOID                        Instrumentation[16];               /* f2c/16b8 */
	PVOID                        WinSockData;                       /* f6c/1738 */
	ULONG                        GdiBatchCount;                     /* f70/1740 */
	ULONG                        Spare2;                            /* f74/1744 */
	ULONG                        GuaranteedStackBytes;              /* f78/1748 */
	PVOID                        ReservedForPerf;                   /* f7c/1750 */
	PVOID                        ReservedForOle;                    /* f80/1758 */
	ULONG                        WaitingOnLoaderLock;               /* f84/1760 */
	PVOID                        Reserved5[3];                      /* f88/1768 */
	PVOID* TlsExpansionSlots;                 /* f94/1780 */
#ifdef _WIN64
	PVOID                        DeallocationBStore;                /*    /1788 */
	PVOID                        BStoreLimit;                       /*    /1790 */
#endif
	ULONG                        ImpersonationLocale;               /* f98/1798 */
	ULONG                        IsImpersonating;                   /* f9c/179c */
	PVOID                        NlsCache;                          /* fa0/17a0 */
	PVOID                        ShimData;                          /* fa4/17a8 */
	ULONG                        HeapVirtualAffinity;               /* fa8/17b0 */
	PVOID                        CurrentTransactionHandle;          /* fac/17b8 */
	TEB_ACTIVE_FRAME* ActiveFrame;                       /* fb0/17c0 */
	TEB_FLS_DATA* FlsSlots;                          /* fb4/17c8 */
	PVOID                        PreferredLanguages;                /* fb8/17d0 */
	PVOID                        UserPrefLanguages;                 /* fbc/17d8 */
	PVOID                        MergedPrefLanguages;               /* fc0/17e0 */
	ULONG                        MuiImpersonation;                  /* fc4/17e8 */
	USHORT                       CrossTebFlags;                     /* fc8/17ec */
	USHORT                       SameTebFlags;                      /* fca/17ee */
	PVOID                        TxnScopeEnterCallback;             /* fcc/17f0 */
	PVOID                        TxnScopeExitCallback;              /* fd0/17f8 */
	PVOID                        TxnScopeContext;                   /* fd4/1800 */
	ULONG                        LockCount;                         /* fd8/1808 */
	LONG                         WowTebOffset;                      /* fdc/180c */
	PVOID                        ResourceRetValue;                  /* fe0/1810 */
	PVOID                        ReservedForWdf;                    /* fe4/1818 */
	ULONGLONG                    ReservedForCrt;                    /* fe8/1820 */
	GUID                         EffectiveContainerId;              /* ff0/1828 */
} __TEB, * __PTEB;

typedef struct _WOW64INFO
{
	ULONG   NativeSystemPageSize;
	ULONG   CpuFlags;
	ULONG   Wow64ExecuteFlags;
	ULONG   unknown[5];
	USHORT  NativeMachineType;
	USHORT  EmulatedMachineType;
} WOW64INFO;

#if 0

#define __u32 UINT32
#define __u64 UINT64

/* for KVM_SET_USER_MEMORY_REGION */
struct kvm_userspace_memory_region {
	__u32 slot;
	__u32 flags;
	__u64 guest_phys_addr;
	__u64 memory_size; /* bytes */
	__u64 userspace_addr; /* start of the userspace allocated memory */
};

/* for KVM_SET_USER_MEMORY_REGION2 */
struct kvm_userspace_memory_region2 {
	__u32 slot;
	__u32 flags;
	__u64 guest_phys_addr;
	__u64 memory_size;
	__u64 userspace_addr;
	__u64 guest_memfd_offset;
	__u32 guest_memfd;
	__u32 pad1;
	__u64 pad2[14];
};
#endif

#ifdef __cplusplus
extern "C" {
#endif

	__declspec(dllexport) void* WINAPI BTCpuGetBopCode(void) { return (UINT32*)&bopcode; }
	__declspec(dllexport) NTSTATUS WINAPI BTCpuGetContext(HANDLE thread, HANDLE process, void* unknown, ARM_CONTEXT* ctx) { return NtQueryInformationThread_alternative(thread, ThreadWow64Context, ctx, sizeof(*ctx), NULL); }
	__declspec(dllexport) NTSTATUS WINAPI BTCpuProcessInit(void) { if ((ULONG_PTR)BTCpuProcessInit >> 32) { return STATUS_INVALID_ADDRESS; } return STATUS_SUCCESS; }
	__declspec(dllexport) NTSTATUS WINAPI BTCpuThreadInit(void) { return STATUS_SUCCESS; }
	__declspec(dllexport) NTSTATUS WINAPI BTCpuResetToConsistentState(EXCEPTION_POINTERS* ptrs) { return STATUS_SUCCESS; }
	__declspec(dllexport) NTSTATUS WINAPI BTCpuSetContext(HANDLE thread, HANDLE process, void* unknown, ARM_CONTEXT* ctx) { return NtSetInformationThread_alternative(thread, ThreadWow64Context, ctx, sizeof(*ctx)); }
	__declspec(dllexport) void WINAPI BTCpuSimulate(void) {
		ARM_CONTEXT* wow_context;
		struct kvm_regs regs;
		NTSTATUS ret;
		RtlWow64GetCurrentCpuArea(NULL, (void**)&wow_context, NULL);
		int kvmfd = open("/dev/kvm", O_RDWR | O_CLOEXEC, 0);
		if (kvmfd < 0) return;
		int api_ver = ioctl(kvmfd, KVM_GET_API_VERSION, 0);
		int vmfd = ioctl(kvmfd, KVM_CREATE_VM, 0);
		if (vmfd < 0) return;
		struct kvm_userspace_memory_region region;
		region.slot = 0;
		region.flags = 0;
		region.guest_phys_addr = 0;
		region.memory_size = 0x100000000;
		region.userspace_addr = 0;
		if (ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, (unsigned int)&region) < 0) {
			return;
		}
		int vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, 0);
		if (vcpufd < 0) return;
		size_t vcpu_mmap_size = ioctl(kvmfd, KVM_GET_VCPU_MMAP_SIZE, NULL);
		struct kvm_run* run = (struct kvm_run*)mmap(0,
			vcpu_mmap_size,
			PROT_READ | PROT_WRITE,
			MAP_SHARED,
			vcpufd, 0);
emuresume:
		UINT8 svctype = 0;
		bool emustopped = false;
		if (ioctl(vcpufd, KVM_GET_REGS, (unsigned int)&regs) >= 0) {
			regs.regs.regs[0] = wow_context->R0;
			regs.regs.regs[1] = wow_context->R1;
			regs.regs.regs[2] = wow_context->R2;
			regs.regs.regs[3] = wow_context->R3;
			regs.regs.regs[4] = wow_context->R4;
			regs.regs.regs[5] = wow_context->R5;
			regs.regs.regs[6] = wow_context->R6;
			regs.regs.regs[7] = wow_context->R7;
			regs.regs.regs[8] = wow_context->R8;
			regs.regs.regs[9] = wow_context->R9;
			regs.regs.regs[10] = wow_context->R10;
			regs.regs.regs[11] = wow_context->R11;
			regs.regs.regs[12] = wow_context->R12;
			regs.regs.regs[13] = wow_context->Sp;
			regs.regs.regs[14] = wow_context->Lr;
			regs.regs.pc = wow_context->Pc & 0xFFFFFFFE;
			regs.regs.pstate = wow_context->Cpsr | 0x1f | ((wow_context->Pc&1) << 5);
			regs.fp_regs.fpsr = wow_context->Fpscr & 0xF800009F;
			regs.fp_regs.fpcr = wow_context->Fpscr & 0x07F79F00;
			for (int cnt = 0; cnt < 16; cnt++) { regs.fp_regs.vregs[cnt].q[0] = wow_context->Q[cnt].Low; regs.fp_regs.vregs[cnt].q[1] = wow_context->Q[cnt].High; }
			if (ioctl(vcpufd, KVM_SET_REGS, (unsigned int)&regs) < 0) { return; }
		}
		else { return; }
		while (emustopped == false) {
			ioctl(vcpufd, KVM_RUN, NULL);
			switch (run->exit_reason) {
			case KVM_EXIT_HYPERCALL:
				emustopped = true;
				break;
			default:
			}
		}
		if (ioctl(vcpufd, KVM_GET_REGS, (unsigned int)&regs) >= 0) {
			wow_context->R0 = regs.regs.regs[0];
			wow_context->R1 = regs.regs.regs[1];
			wow_context->R2 = regs.regs.regs[2];
			wow_context->R3 = regs.regs.regs[3];
			wow_context->R4 = regs.regs.regs[4];
			wow_context->R5 = regs.regs.regs[5];
			wow_context->R6 = regs.regs.regs[6];
			wow_context->R7 = regs.regs.regs[7];
			wow_context->R8 = regs.regs.regs[8];
			wow_context->R9 = regs.regs.regs[9];
			wow_context->R10 = regs.regs.regs[10];
			wow_context->R11 = regs.regs.regs[11];
			wow_context->R12 = regs.regs.regs[12];
			wow_context->Sp = regs.regs.regs[13];
			wow_context->Lr = regs.regs.regs[14];
			wow_context->Pc = regs.regs.pc | ((regs.regs.pstate >> 5) & 1);
			wow_context->Cpsr = regs.regs.pstate;
			wow_context->Fpscr = (regs.fp_regs.fpcr | regs.fp_regs.fpsr);
			for (int cnt = 0; cnt < 16; cnt++) { wow_context->Q[cnt].Low = regs.fp_regs.vregs[cnt].q[0]; wow_context->Q[cnt].High = regs.fp_regs.vregs[cnt].q[1]; }
		}
		else { return; }
		UINT32 hvctmp = (*(UINT32*)(wow_context->Pc & 0xFFFFFFFE));
		svctype = (((hvctmp>>8)&0xFF) | (((hvctmp >> 0) & 0xF) << 8) | (((hvctmp >> 24) & 0xF) << 12));
	switch (svctype) {
	case 1:
		wow_context->R0 = Wow64SystemServiceEx(wow_context->R12, (UINT*)ULongToPtr(wow_context->Sp));
		wow_context->Pc = wow_context->Lr;
		wow_context->Lr = wow_context->R3;
		wow_context->Sp += 4 * 4;
		goto emuresume;
		break;
	case 2:
		if (p__wine_unix_call != 0) {
			UINT32* p = (UINT32*)wow_context->R0;
			wow_context->R0 = p__wine_unix_call((*(UINT64*)((void*)&p[0])), wow_context->R2, ULongToPtr(wow_context->R3));
		}
		else { wow_context->R0 = -1; }
		wow_context->Pc = wow_context->Lr;
		goto emuresume;
		break;
	}
	return;
	}
	__declspec(dllexport) void* WINAPI __wine_get_unix_opcode(void) { return (UINT32*)&unixbopcode; }
	__declspec(dllexport) BOOLEAN WINAPI BTCpuIsProcessorFeaturePresent(UINT feature) { if (feature == 2 || feature == 3 || feature == 6 || feature == 7 || feature == 8 || feature == 10 || feature == 13 || feature == 17 || feature == 36 || feature == 37 || feature == 38) { return true; } return false; }
	__declspec(dllexport) NTSTATUS WINAPI BTCpuTurboThunkControl(ULONG enable) { if (enable) { return STATUS_NOT_SUPPORTED; } return STATUS_SUCCESS; }

#ifdef __cplusplus
}
#endif
