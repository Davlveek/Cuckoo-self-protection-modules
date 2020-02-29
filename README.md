# Cuckoo-self-protection-modules

## Anti Debug modules
Checking static data from Cuckoo global container and behavior data from created processing module.
This module detect following methods:
- IsDebuggerPresent
- CheckRemoteDebuggerPresent
- GetVersionExA
- GetThreadContext
- NtSetInformationThread
- NtCreateThreadEx
- NtQueryInformationProcess

Signatures:
- debuggercheck - detect API calls: IsDebuggerPresent, CheckRemoteDebuggerPresent and SystemKernelDebuggerInformation

## Anti VM modules
Checking static data from Cuckoo global container.
This modules detect following artifacts:
- Filesystem artifacts
- WMI-requests
- DLLs
- Processes
- Hostnames
- Registry keys
- MAC Adresses
- Virtual devices

Signatures:
- devicecheck - checking opened files of virtual devices
- disksize - detect GetDiskFreeSpace API calls
- enumservices - detect EnumServicesStatus API calls
- filescheck - cheking opened files and loaded DLLs
- regkeyscheck - checking opened registry keys
