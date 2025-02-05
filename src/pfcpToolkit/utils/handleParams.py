from src.pfcpToolkit.utils.logger import Log


class HandleParams:
    def __init__(self, classPrefix=""):
        self.basePrefix = f"[HandleParams]{classPrefix}"
        self.logger = Log(self.basePrefix)
        self.default_error_messages = {
            "src_addr": "No source address provided. Expected a valid IPv4 address (e.g., '192.168.1.1').",
            "dest_addr": "No destination address provided. Expected a valid IPv4 address (e.g., '192.168.1.2').",
            "src_port": "No source port provided. Expected a valid port number (e.g., 8805).",
            "dest_port": "No destination port provided. Expected a valid port number (e.g., 8805).",
            "seid": "No SEID provided. Expected a valid SEID (e.g., 0xC0FFEE).",
            "evil_addr": "No evil address provided.",
            "upf_addr": "No UPF address provided.",
            "smf_addr": "No SMF address provided.",
            "ue_addr": "No UE address provided.",
            "target_seid": "No SEID provided.",
            "far_id": "No FAR ID provided.",
            "update_ie": "No Update IE provided.",
            "far_range": "No FAR ID range provided.",
            "session_range": "No Session ID range provided.",
        }

    def set_method_prefix(self, prefix):
        self.logger.set_prefix(self.basePrefix + prefix)

    def check_parameters(self, params_required: dict, method_prefix=""):
        ret_val = True
        self.set_method_prefix(method_prefix)
        for param_name, param_value in params_required.items():
            if param_value is None or not param_value:
                error_message = self.default_error_messages.get(
                    param_name, f"No {param_name} provided. Expected a valid value."
                )
                self.logger.error(f"Error: {error_message}")
                ret_val = False

        if not ret_val:
            self.logger.error("Error: Invalid parameters provided.")

        return ret_val
