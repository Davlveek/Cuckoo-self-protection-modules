from cuckoo.common.abstracts import Signature

class ChekDevices(Signature):
    name = "virtual_devices"
    description = "Detects checking virtual devices"
    severity = 2
    categories = ["anti-vm"]
    authors = ["davlveek"]
    minimum = "2.0"

    devices_regex = [
        ".*VBox(MiniRdrDN|Guest|Mouse|Video|TrayIPC)$",
        ".*vmci$",
        ".*HGFS$"
    ]

    def on_complete(self):
        for regex in self.devices_regex:
            for device in self.check_file(pattern=regex, regex=True, all=True):
                self.mark_ioc("device", device)

        return self.has_marks()
