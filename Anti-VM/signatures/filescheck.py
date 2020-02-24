from cuckoo.common.abstracts import Signature

class CheckFiles(Signature):
    name = "virtual_devices"
    description = "Detects checking files"
    severity = 2
    categories = ["anti-vm"]
    authors = ["davlveek"]
    minimum = "2.0"

    files_regex = [
        ".*vboxservice\\.exe",
        ".*vboxtray\\.exe",
        ".*vmtoolsd\\.exe",
        ".*vmwaretray\\.exe",
        ".*VGAuthService\\.exe",
        ".*vmacthlp\\.exe",
        ".*vmsrvc\\.exe",
        ".*vmusrvc\\.exe",
        ".*prl_cc\\.exe",
        ".*prl_tools\\.exe",
        ".*xenservice\\.exe",
        ".*qemu-ga\\.exe",
        ".*vboxdisp\\.dll",
        ".*vboxhook\\.dll",
        ".*vboxmrxnp\\.dll",
        ".*vboxogl\\.dll",
        ".*vboxoglarrayspu\\.dll",
        ".*vboxoglcrutil\\.dll",
        ".*vboxoglerrorspu\\.dll",
        ".*vboxoglfeedbackspu\\.dll",
        ".*vboxoglpackspu\\.dll",
        ".*vboxoglpassthroughspu\\.dll",
        ".*VBoxControl\\.exe",
    ]

    def on_complete(self):
        for regex in self.files_regex:
            if self.check_file(pattern=regex, regex=True): 
                self.mark_ioc("file", file)
            elif self.check_dll_loaded(pattern=regex, regex=True):
                self.mark_ioc("file", file)

        return self.has_marks()