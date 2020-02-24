from cuckoo.common.abstracts import Signature

class EnumServices(Signature):
    name = "enum_services"
    description = "Checking services"
    severity = 2
    categories = ["anti-vm"]
    authors = ["davlveek"]
    minimum = "2.0"

    def on_call(self, call, process):
        if call["api"].startswith("EnumServicesStatus"):
            self.mark_call()

    def on_complete(self):
        return self.has_marks()