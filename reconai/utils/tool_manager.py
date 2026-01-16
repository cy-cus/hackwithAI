import shutil
import subprocess
import logging
from pathlib import Path
import asyncio

logger = logging.getLogger(__name__)

class ToolManager:
    def __init__(self):
        self.tools = {
            "subfinder": {
                "check": "subfinder",
                "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            },
            "amass": {
                "check": "amass",
                "install": "go install -v github.com/owasp-amass/amass/v4/...@master"
            },
            "httpx": {
                "check": "httpx",
                "install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
            },
            "katana": {
                "check": "katana",
                "install": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
            },
            "waybackurls": {
                "check": "waybackurls",
                "install": "go install github.com/tomnomnom/waybackurls@latest"
            },
            "nuclei": {
                "check": "nuclei",
                "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            }
        }

    def check_tool(self, tool_name: str) -> bool:
        """Check if a tool is installed (available in PATH)."""
        tool_config = self.tools.get(tool_name)
        if not tool_config:
            # Python-based or internal tools are always "installed"
            return True
        
        return shutil.which(tool_config["check"]) is not None

    def get_all_tool_status(self) -> dict:
        """Get status of all managed tools."""
        status = {}
        for tool in self.tools:
            status[tool] = self.check_tool(tool)
        return status

    async def install_tool(self, tool_name: str) -> bool:
        """Install a tool using its install command."""
        tool_config = self.tools.get(tool_name)
        if not tool_config:
            return False

        if self.check_tool(tool_name):
            return True

        cmd = tool_config["install"]
        logger.info(f"Installing {tool_name} with command: {cmd}")
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                logger.info(f"Successfully installed {tool_name}")
                return True
            else:
                logger.error(f"Failed to install {tool_name}: {stderr.decode()}")
                return False
        except Exception as e:
            logger.error(f"Exception installing {tool_name}: {e}")
            return False
