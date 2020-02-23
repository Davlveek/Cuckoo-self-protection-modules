import os
import json

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooReportError

fs_artifacts = [
                    "system32\\drivers\\VBoxMouse.sys",
                    "system32\\drivers\\VBoxGuest.sys",
                    "system32\\drivers\\VBoxSF.sys",
                    "system32\\drivers\\VBoxVideo.sys",
                    "system32\\vboxdisp.dll",
                    "system32\\vboxhook.dll",
                    "system32\\vboxmrxnp.dll",
                    "system32\\vboxogl.dll",
                    "system32\\vboxoglarrayspu.dll",
                    "system32\\vboxoglcrutil.dll",
                    "system32\\vboxoglerrorspu.dll",
                    "system32\\vboxoglfeedbackspu.dll",
                    "system32\\vboxoglpackspu.dll",
                    "system32\\vboxoglpassthroughspu.dll",
                    "system32\\vboxservice.exe",
                    "system32\\vboxtray.exe",
                    "system32\\VBoxControl.exe",
                    "system32\\drivers\\vmmouse.sys",
                    "system32\\drivers\\vmhgfs.sys",
                    "system32\\drivers\\vm3dmp.sys",
                    "system32\\drivers\\vmci.sys",
                    "system32\\drivers\\vmhgfs.sys",
                    "system32\\drivers\\vmmemctl.sys",
                    "system32\\drivers\\vmmouse.sys",
                    "system32\\drivers\\vmrawdsk.sys",
                    "system32\\drivers\\vmusbmouse.sys"
                ]

wmi_requests = [
                    "SELECT * FROM Win32_Bios",
                    "SELECT * FROM Win32_PnPEntity",
                    "SELECT * FROM Win32_NetworkAdapterConfiguration",
                    "SELECT * FROM Win32_NTEventlogFile",
                    "SELECT * FROM Win32_Processor",
                    "SELECT * FROM Win32_LogicalDisk",
                    "SELECT * FROM Win32_ComputerSystem",
                    "SELECT * FROM MSAcpi_ThermalZoneTemperature",
                    "SELECT * FROM Win32_Fan"
               ]

dlls = [    
            "avghookx.dll",
            "avghooka.dll",
            "snxhk.dll",
            "sbiedll.dll", 
            "dbghelp.dll",
            "api_log.dll",
            "dir_watch.dll", 
            "pstorec.dll",
            "vmcheck.dll",
            "wpespy.dll",
            "cmdvrt32.dll",
            "cmdvrt64.dll"
       ]

processes = [
                "vboxservice.exe",
                "vboxtray.exe",
                "vmtoolsd.exe",
                "vmwaretray.exe",
                "vmwareuser",
                "VGAuthService.exe",
                "vmacthlp.exe",
                "vmsrvc.exe",
                "vmusrvc.exe",
                "prl_cc.exe",
                "prl_tools.exe",
                "xenservice.exe",
                "qemu-ga.exe"
            ]

hostnames = [
                "brbrb-d8fb22af1",
                "KVMKVMKVM", 
                "prl hyperv", 
                "Microsoft Hv", 
                "XenVMMXenVMM"
            ]

registry_keys = [
                    "HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0",
                    "HARDWARE\Description\System",
                    "HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0",
                    "HARDWARE\DEVICEMAP\Scsi\Scsi Port 1\Scsi Bus 0\Target Id 0\Logical Unit Id 0",
                    "HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0",
                    "SYSTEM\ControlSet001\Control\SystemInformation",
                    "HARDWARE\ACPI\DSDT\VBOX",
                    "HARDWARE\ACPI\FADT\VBOX",
                    "HARDWARE\ACPI\RSDT\VBOX",
                    "SOFTWARE\Oracle\VirtualBox Guest Additions",
                    "SYSTEM\ControlSet001\Services\VBoxGuest",
                    "SYSTEM\ControlSet001\Services\VBoxMouse",
                    "SYSTEM\ControlSet001\Services\VBoxService",
                    "SYSTEM\ControlSet001\Services\VBoxSF",
                    "SYSTEM\ControlSet001\Services\VBoxVideo",
                    "SOFTWARE\VMware, Inc.\VMware Tools",
                    "SOFTWARE\Wine",
                    "SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"
                ]

class AntiVmReport(Report):
    def run(self, results):
        try:
            anti_vm_report = open(os.path.join(self.reports_path, "anti_vm_report.json"), "w")
            anti_vm_dict = self.check_anti_vm(results)
            json.dump(anti_vm_dict, anti_vm_report, sort_keys=False, indent=4)
            anti_vm_report.close()
        except (TypeError, IOError) as e:
            raise CuckooReportError("Failed to make anti vm report %s" % e)


    def check_anti_vm(self, results):
        anti_vm_dict = dict()
        # Get strings list
        strings_list = results["strings"]

        # Init lists
        fs_artifacts_list = list()
        hostnames_list = list()
        wmi_requests_list = list()
        dll_list = list()
        process_list = list()
        registry_list = list()

        for string in strings_list:
            # Check filesystem artifacts
            for fs_artifact in fs_artifacts:
                if string == fs_artifact:
                    fs_artifacts_list.append(fs_artifact)
            
            # Check WMI requests
            for wmi_request in wmi_requests:
                if string == wmi_request:
                    wmi_requests_list.append(wmi_request)

            # Check DLLs
            for dll in dlls:
                if string == dll:
                    dll_list.append(dll)

            # Check processes
            for process in processes:
                if string == process:
                    process_list.append(process)

            # Check hostnames
            for hostname in hostnames:
                if string == hostname:
                    hostnames_list.append(hostname)

            # Check registry keys
            for key in registry_keys:
                if string == key:
                    registry_list.append(key)

        # Set results
        anti_vm_dict["Filesystem artifacts"] = fs_artifacts_list
        anti_vm_dict["WMI requests"] = wmi_requests_list
        anti_vm_dict["DLLs"] = dll_list
        anti_vm_dict["Processes"] = process_list
        anti_vm_dict["Hostnames"] = hostnames_list
        anti_vm_dict["Registry keys"] = registry_list

        return anti_vm_dict