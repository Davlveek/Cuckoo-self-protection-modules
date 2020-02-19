import os
import json
import calendar
import datetime

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooReportError

anti_debug_api_list = [
                        "IsDebuggerPresent", "GetVersionExA",
                        "GetThreadContext", "NtSetInformationThread",
                        "NtCreateThreadEx", "NtQueryInformationProcess",
                        "CheckRemoteDebuggerPresent"
                      ]

def default(obj):
    if isinstance(obj, datetime.datetime):
        if obj.utcoffset() is not None:
            obj = obj - obj.utcoffset()
        return calendar.timegm(obj.timetuple()) + obj.microsecond / 1000000.0
    raise TypeError("%r is not JSON serializable" % obj)

class AntiDebugReport(Report):
    def get_target(self, results):
        return results["target"]["file"]["name"]

    def check_static_data(self, results):
        anti_debug_api_dict = dict()

        # Check imports
        static_dict = results["static"]
        pe_imports_dict_list = static_dict["pe_imports"]

        for lib in pe_imports_dict_list:
            imports = lib["imports"]
            for Import in imports:
                for api in anti_debug_api_list:
                    if api == Import["name"]:
                        anti_debug_api_dict[api] = True

        # Filling not found api
        for api in anti_debug_api_list:
            if api not in anti_debug_api_dict:
                anti_debug_api_dict[api] = False

        return anti_debug_api_dict

    def check_behavior_data(self, results, behavior):
        anti_debug_behavior = dict()

        target = self.get_target(results)
        calls = dict()
        for process in behavior["processes"]:
            if process["process_name"] == target:
                calls = process["calls"]

        # Check calls
        for call in calls:
            if call["api"] == "LdrGetProcedureAddress":
                arguments = call["arguments"]
                for api in anti_debug_api_list:
                    if api == arguments["function_name"]:
                        anti_debug_behavior[api] = True

        # Filling not found api
        for api in anti_debug_api_list:
            if api not in anti_debug_behavior:
                anti_debug_behavior[api] = False

        return anti_debug_behavior

    def run(self, results):
        try:
            # Form report of static data
            anti_debug_static = open(os.path.join(self.reports_path, "anti_debug_static.json"), "w")
            anti_debug_static_dict = self.check_static_data(results)
            json.dump(anti_debug_static_dict, anti_debug_static, sort_keys=False, indent=4)
            anti_debug_static.close()

            # Form report of behavior data
            behavior = results["anti_debug"]
            anti_debug_behavior = open(os.path.join(self.reports_path, "anti_debug_behavior.json"), "w")
            anti_debug_behavior_dict = self.check_behavior_data(results, behavior)
            json.dump(anti_debug_behavior_dict, anti_debug_behavior, sort_keys=False, indent=4)
            anti_debug_behavior.close()
        except (TypeError, IOError) as e:
            raise CuckooReportError("Failed to make anti debug report %s" % e)