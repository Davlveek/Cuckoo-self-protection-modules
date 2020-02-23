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
