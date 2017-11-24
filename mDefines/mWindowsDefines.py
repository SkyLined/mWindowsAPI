import ctypes;

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
DEBUG_ONLY_THIS_PROCESS                 = 0x00000002
DEBUG_PROCESS                           = 0x00000001
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
SYNCHRONIZE                             = 0x00100000;
#TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT
TH32CS_INHERIT                          = 0x80000000;
TH32CS_SNAPALL                          = 0x0000000F;
TH32CS_SNAPHEAPLIST                     = 0x00000001;
TH32CS_SNAPMODULE                       = 0x00000008;
TH32CS_SNAPMODULE32                     = 0x00000010;
TH32CS_SNAPPROCESS                      = 0x00000002;
TH32CS_SNAPTHREAD                       = 0x00000004;
# THREAD_ALL_ACCESS	                      =     0x0fff; # Not a static number across versions, do not use!
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
WRITE_DAC                               = 0x00040000;
WRITE_OWNER                             = 0x00080000;
