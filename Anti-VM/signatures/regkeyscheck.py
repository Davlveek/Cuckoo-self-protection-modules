from cuckoo.common.abstracts import Signature

class CheckRegKeys(Signature):
    name = "registry_keys"
    description = "Detects checking registry keys"
    severity = 2
    categories = ["anti-vm"]
    authors = ["davlveek"]
    minimum = "2.0"

    regkeys_regex = [
        "HARDWARE\\\\ACPI\\\\(DSDT|FADT|RSDT)\\\\VBOX",
        "HARDWARE\\\\DEVICEMAP\\\\Scsi\\\\Scsi Port (0|1|2)\\\\Scsi Bus 0\\\\Target Id 0\\\\Logical Unit Id 0",
        "SOFTWARE\\\\Oracle\\\\VirtualBox Guest Additions",
        "SYSTEM\\\\ControlSet001\\\\Services\\\\Vbox(Mouse|Guest|Service|SF|Video)",
        "SOFTWARE\\\\VMware, Inc.\\\\\VMware Tools",
        "SOFTWARE\\\\Wine",
        "SOFTWARE\\\\Microsoft\\\\Virtual Machine\\\\Guest\\\\Parameters",
        "HARDWARE\\\\Description\\\\System",
        "SYSTEM\\\\ControlSet001\\\\Control\\\\SystemInformation",
        ]

    def on_complete(self):
        for regex in self.regkeys_regex:
            for regkey in self.check_key(pattern=regex, regex=True, all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()