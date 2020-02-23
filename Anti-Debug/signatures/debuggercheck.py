from cuckoo.common.abstracts import Signature

class CheckDebugger(Signature):
    name = "check_debugger"
    description = "Check if process is being debugged"
    severity = 2
    categories = ["anti-debug"]
    authors = ["davlveek"]
    minimum = "2.0"

    filter_apinames = [
                            "IsDebuggerPresent",
                            "CheckRemoteDebuggerPresent"
                      ]

    def on_call(self, call, process):
        self.mark_call()

    def on_complete(self):
        return self.has_marks()

class CheckKernelDebugger(Signature):
    name = "check_kernel_debugger"
    description = "Check if process is being debugged by a kernel debugger"
    severity = 2
    categories = ["anti-debug"]
    authors = ["davlveek"]
    minimum = "2.0"

    filter_apinames = [ "SystemKernelDebuggerInformation" ]

    def on_call(self, call, process):
        self.mark_call()

    def on_complete(self):
        return self.has_marks()
