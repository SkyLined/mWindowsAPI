import ctypes, struct;

################################################################################
# Non-numeric defines
################################################################################
FALSE = False;
NULL = None;
TRUE = True;

################################################################################
# Numeric defines
################################################################################

#CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
CREATE_BREAKAWAY_FROM_JOB               = 0x01000000;
CREATE_DEFAULT_ERROR_MODE               = 0x04000000;
CREATE_NEW_CONSOLE                      = 0x00000010;
CREATE_NEW_PROCESS_GROUP                = 0x00000200;
CREATE_NO_WINDOW                        = 0x08000000;
CREATE_PROTECTED_PROCESS                = 0x00040000;
CREATE_PRESERVE_CODE_AUTHZ_LEVEL        = 0x02000000;
CREATE_SEPARATE_WOW_VDM                 = 0x00000800;
CREATE_SHARED_WOW_VDM                   = 0x00001000;
CREATE_SUSPENDED                        = 0x00000004;
CREATE_UNICODE_ENVIRONMENT              = 0x00000400;
CTRL_BREAK_EVENT                        =          1; # https://docs.microsoft.com/en-us/windows/console/generateconsolectrlevent
CTRL_C_EVENT                            =          0; # https://docs.microsoft.com/en-us/windows/console/generateconsolectrlevent
#DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
DEBUG_ONLY_THIS_PROCESS                 = 0x00000002;
DEBUG_PROCESS                           = 0x00000001;
DELETE                                  = 0x00010000;
DETACHED_PROCESS                        = 0x00000008;
DUPLICATE_CLOSE_SOURCE                  = 0x00000001;
DUPLICATE_SAME_ACCESS                   = 0x00000002;
#EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
EXTENDED_STARTUPINFO_PRESENT            = 0x00080000
#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
#HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
HANDLE_FLAG_INHERIT                     = 0x00000001;
HANDLE_FLAG_PROTECT_FROM_CLOSE          = 0x00000002;
HEAP_ZERO_MEMORY                        = 0x00000008;
#IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE   =     0x0040;
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY =    0x0080;
IMAGE_DLLCHARACTERISTICS_NO_BIND        =     0x0800;
IMAGE_DLLCHARACTERISTICS_NO_ISOLATION   =     0x0200;
IMAGE_DLLCHARACTERISTICS_NO_SEH         =     0x0400;
IMAGE_DLLCHARACTERISTICS_NX_COMPAT      =     0x0100;
IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000;
IMAGE_DLLCHARACTERISTICS_WDM_DRIVER     =     0x2000;
IMAGE_NT_OPTIONAL_HDR32_MAGIC           =      0x10b;
IMAGE_NT_OPTIONAL_HDR64_MAGIC           =      0x20b;
IMAGE_ROM_OPTIONAL_HDR_MAGIC            =      0x107;
IMAGE_SUBSYSTEM_EFI_APPLICATION         =         10;
IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER =         11;
IMAGE_SUBSYSTEM_EFI_ROM                 =         13;
IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER      =         12;
IMAGE_SUBSYSTEM_NATIVE                  =          1;
IMAGE_SUBSYSTEM_OS2_CUI                 =          5;
IMAGE_SUBSYSTEM_POSIX_CUI               =          7;
IMAGE_SUBSYSTEM_UNKNOWN                 =          0;
IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION =        16;
IMAGE_SUBSYSTEM_WINDOWS_CE_GUI          =          9;
IMAGE_SUBSYSTEM_WINDOWS_CUI             =          3;
IMAGE_SUBSYSTEM_WINDOWS_GUI             =          2;
IMAGE_SUBSYSTEM_XBOX                    =         14;
INFINITE                                = 0xFFFFFFFF;
INHERIT_PARENT_AFFINITY                 = 0x00010000
INVALID_FILE_SIZE                       = 0xFFFFFFFF;
INVALID_HANDLE_VALUE                    = ctypes.c_void_p(-1).value;
#JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ
JOB_OBJECT_LIMIT_ACTIVE_PROCESS         = 0x00000008;
JOB_OBJECT_LIMIT_AFFINITY               = 0x00000010;
JOB_OBJECT_LIMIT_BREAKAWAY_OK           = 0x00000800;
JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
JOB_OBJECT_LIMIT_JOB_MEMORY             = 0x00000200;
JOB_OBJECT_LIMIT_JOB_TIME               = 0x00000004;
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE      = 0x00002000;
JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME      = 0x00000040;
JOB_OBJECT_LIMIT_PRIORITY_CLASS         = 0x00000020;
JOB_OBJECT_LIMIT_PROCESS_MEMORY         = 0x00000100;
JOB_OBJECT_LIMIT_PROCESS_TIME           = 0x00000002;
JOB_OBJECT_LIMIT_SCHEDULING_CLASS       = 0x00000080;
JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK    = 0x00001000;
JOB_OBJECT_LIMIT_SUBSET_AFFINITY        = 0x00004000;
JOB_OBJECT_LIMIT_WORKINGSET             = 0x00000001;
JobObjectAssociateCompletionPortInformation =      7;
JobObjectBasicAccountingInformation     =          1;
JobObjectBasicAndIoAccountingInformation =         8;
JobObjectBasicLimitInformation          =          2;
JobObjectBasicProcessIdList             =          3;
JobObjectBasicUIRestrictions            =          4;
JobObjectCpuRateControlInformation      =         15;
JobObjectLimitViolationInformation      =         13;
JobObjectEndOfJobTimeInformation        =          6;
JobObjectExtendedLimitInformation       =          9;
JobObjectGroupInformation               =         11;
JobObjectGroupInformationEx             =         14;
JobObjectLimitViolationInformation2     =         35;
JobObjectNetRateControlInformation      =         32;
JobObjectNotificationLimitInformation   =         12;
JobObjectNotificationLimitInformation2  =         34;
JobObjectSecurityLimitInformation       =          5;
#MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MAX_MODULE_NAME32                       =        255;
MAX_PATH                                =        260;
MEM_COMMIT                              =     0x1000;
MEM_DECOMMIT                            =     0x4000;
MEM_FREE                                =    0x10000;
MEM_IMAGE                               =  0x1000000;
MEM_MAPPED                              =    0x40000;
MEM_PRIVATE                             =    0x20000;
MEM_RELEASE                             =     0x8000;
MEM_RESERVE                             =     0x2000;
#NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
#PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
PAGE_EXECUTE                            =       0x10;
PAGE_EXECUTE_READ                       =       0x20;
PAGE_EXECUTE_READWRITE                  =       0x40;
PAGE_EXECUTE_WRITECOPY                  =       0x80;
PAGE_NOACCESS                           =        0x1;
PAGE_READONLY                           =        0x2;
PAGE_READWRITE                          =        0x4;
PAGE_WRITECOPY                          =        0x8;
PROCESS_ALL_ACCESS                      =   0x1F0FFF;
PROCESS_CREATE_PROCESS                  =     0x0080;
PROCESS_CREATE_THREAD                   =     0x0002;
PROCESS_DUP_HANDLE                      =     0x0040;
PROCESS_QUERY_INFORMATION               =     0x0400;
PROCESS_QUERY_LIMITED_INFORMATION       =     0x1000;
PROCESS_SET_INFORMATION                 =     0x0200;
PROCESS_SET_QUOTA                       =     0x0100;
PROCESS_SUSPEND_RESUME                  =     0x0800;
PROCESS_TERMINATE                       =     0x0001;
PROCESS_VM_OPERATION                    =     0x0008;
PROCESS_VM_READ                         =     0x0010;
PROCESS_VM_WRITE                        =     0x0020;
ProcessBasicInformation                 =          0;
ProcessDebugPort                        =          7;
ProcessWow64Information                 =         26;
ProcessImageFileName                    =         27;
ProcessBreakOnTermination               =         29;
PROCESSOR_ARCHITECTURE_AMD64            =          9; # x64
PROCESSOR_ARCHITECTURE_ARM              =          5; # arm
PROCESSOR_ARCHITECTURE_IA64             =          6; # Itanium
PROCESSOR_ARCHITECTURE_INTEL            =          0; # x86
PROCESSOR_ARCHITECTURE_UNKNOWN          =     0xFFFF;
#RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR
READ_CONTROL                            = 0x00020000;
#SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS
STACK_SIZE_PARAM_IS_A_RESERVATION       = 0x00010000;
STARTF_FORCEONFEEDBACK                  = 0x00000040;
STARTF_FORCEOFFFEEDBACK                 = 0x00000080;
STARTF_PREVENTPINNING                   = 0x00002000;
STARTF_RUNFULLSCREEN                    = 0x00000020;
STARTF_TITLEISAPPID                     = 0x00001000;
STARTF_TITLEISLINKNAME                  = 0x00000800;
STARTF_UNTRUSTEDSOURCE                  = 0x00008000;
STARTF_USECOUNTCHARS                    = 0x00000008;
STARTF_USEFILLATTRIBUTE                 = 0x00000010;
STARTF_USEHOTKEY                        = 0x00000200;
STARTF_USEPOSITION                      = 0x00000004;
STARTF_USESHOWWINDOW                    = 0x00000001;
STARTF_USESIZE                          = 0x00000002;
STARTF_USESTDHANDLES                    = 0x00000100;
STILL_ACTIVE                            =      0x103;
STD_ERROR_HANDLE                        =        -12;
STD_INPUT_HANDLE                        =        -10;
STD_OUTPUT_HANDLE                       =        -11;
def STOWED_EXCEPTION_INFORMATION_SIGNATURE(sSignature):
  # This is not actually defined by Windows, but I needed to name this function so I named it similar to
  # STOWED_EXCEPTION_NESTED_TYPE
 return struct.unpack(">L", sSignature)[0]; 
STOWED_EXCEPTION_INFORMATION_V1_SIGNATURE = STOWED_EXCEPTION_INFORMATION_SIGNATURE("SE01");
STOWED_EXCEPTION_INFORMATION_V2_SIGNATURE = STOWED_EXCEPTION_INFORMATION_SIGNATURE("SE02");
def STOWED_EXCEPTION_NESTED_TYPE(sType):
 return struct.unpack("<L", sType)[0]; 
STOWED_EXCEPTION_NESTED_TYPE_NONE       = 0x00000000;
STOWED_EXCEPTION_NESTED_TYPE_WIN32      = STOWED_EXCEPTION_NESTED_TYPE("W32E");
STOWED_EXCEPTION_NESTED_TYPE_STOWED     = STOWED_EXCEPTION_NESTED_TYPE("STOW");
STOWED_EXCEPTION_NESTED_TYPE_CLR        = STOWED_EXCEPTION_NESTED_TYPE("CLR1");
STOWED_EXCEPTION_NESTED_TYPE_LEO        = STOWED_EXCEPTION_NESTED_TYPE("LEO1");
STOWED_EXCEPTION_NESTED_TYPE_LMAX       = STOWED_EXCEPTION_NESTED_TYPE("LMAX"); # Undocumented, reversed from detected exceptions.
SYNCHRONIZE                             = 0x00100000;
#TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT
TH32CS_INHERIT                          = 0x80000000;
TH32CS_SNAPALL                          = 0x0000000F;
TH32CS_SNAPHEAPLIST                     = 0x00000001;
TH32CS_SNAPMODULE                       = 0x00000008;
TH32CS_SNAPMODULE32                     = 0x00000010;
TH32CS_SNAPPROCESS                      = 0x00000002;
TH32CS_SNAPTHREAD                       = 0x00000004;
# THREAD_ALL_ACCESS                       =     0x0fff; # Not a static number across versions, do not use!
THREAD_DIRECT_IMPERSONATION             =     0x0200;
THREAD_GET_CONTEXT                      =     0x0008;
THREAD_IMPERSONATE                      =     0x0100;
THREAD_QUERY_INFORMATION                =     0x0040;
THREAD_QUERY_LIMITED_INFORMATION        =     0x0800;
THREAD_SET_CONTEXT                      =     0x0010;
THREAD_SET_INFORMATION                  =     0x0020;
THREAD_SET_LIMITED_INFORMATION          =     0x0400;
THREAD_SET_THREAD_TOKEN                 =     0x0080;
THREAD_SUSPEND_RESUME                   =     0x0002;
THREAD_TERMINATE                        =     0x0001;
TOKEN_QUERY                             =     0x0008;
TokenIntegrityLevel                     =         25;
#WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WAIT_ABANDONED                          =        128;
WAIT_FAILED                             = 0xFFFFFFFF;
WAIT_OBJECT_0                           =          0;
WAIT_OBJECT_1                           =          1;
WAIT_OBJECT_2                           =          2;
WAIT_OBJECT_3                           =          3;
WAIT_OBJECT_4                           =          4;
WAIT_OBJECT_5                           =          5;
WAIT_OBJECT_6                           =          6;
WAIT_OBJECT_7                           =          7;
WAIT_OBJECT_8                           =          8;
WAIT_OBJECT_9                           =          9;
WAIT_OBJECT_10                          =         10;
WAIT_OBJECT_11                          =         11;
WAIT_OBJECT_12                          =         12;
WAIT_OBJECT_13                          =         13;
WAIT_OBJECT_14                          =         14;
WAIT_OBJECT_15                          =         15;
WAIT_OBJECT_16                          =         16;
WAIT_OBJECT_17                          =         17;
WAIT_OBJECT_18                          =         18;
WAIT_OBJECT_19                          =         19;
WAIT_OBJECT_20                          =         20;
WAIT_OBJECT_21                          =         21;
WAIT_OBJECT_22                          =         22;
WAIT_OBJECT_23                          =         23;
WAIT_OBJECT_24                          =         24;
WAIT_OBJECT_25                          =         25;
WAIT_OBJECT_26                          =         26;
WAIT_OBJECT_27                          =         27;
WAIT_OBJECT_28                          =         28;
WAIT_OBJECT_29                          =         29;
WAIT_OBJECT_30                          =         30;
WAIT_OBJECT_31                          =         31;
WAIT_OBJECT_32                          =         32;
WAIT_OBJECT_33                          =         33;
WAIT_OBJECT_34                          =         34;
WAIT_OBJECT_35                          =         35;
WAIT_OBJECT_36                          =         36;
WAIT_OBJECT_37                          =         37;
WAIT_OBJECT_38                          =         38;
WAIT_OBJECT_39                          =         39;
WAIT_OBJECT_40                          =         40;
WAIT_OBJECT_41                          =         41;
WAIT_OBJECT_42                          =         42;
WAIT_OBJECT_43                          =         43;
WAIT_OBJECT_44                          =         44;
WAIT_OBJECT_45                          =         45;
WAIT_OBJECT_46                          =         46;
WAIT_OBJECT_47                          =         47;
WAIT_OBJECT_48                          =         48;
WAIT_OBJECT_49                          =         49;
WAIT_OBJECT_50                          =         50;
WAIT_OBJECT_51                          =         51;
WAIT_OBJECT_52                          =         52;
WAIT_OBJECT_53                          =         53;
WAIT_OBJECT_54                          =         54;
WAIT_OBJECT_55                          =         55;
WAIT_OBJECT_56                          =         56;
WAIT_OBJECT_57                          =         57;
WAIT_OBJECT_58                          =         58;
WAIT_OBJECT_59                          =         59;
WAIT_OBJECT_60                          =         60;
WAIT_OBJECT_61                          =         61;
WAIT_OBJECT_62                          =         62;
WAIT_OBJECT_63                          =         63;
WAIT_TIMEOUT                            = 0x00000102;
WRITE_DAC                               = 0x00040000;
WRITE_OWNER                             = 0x00080000;
