from cuckoo.common.abstracts import Signature

class DiskSize(Signature):
    name = "virtual_devices"
    description = "Checking disk size"
    severity = 2
    categories = ["anti-vm"]
    authors = ["davlveek"]
    minimum = "2.0"

    def on_call(self, call, process):
        if call["api"].startswith("GetDiskFreeSpace"):
            self.mark_call()

    def on_complete(self):
        return self.has_marks()