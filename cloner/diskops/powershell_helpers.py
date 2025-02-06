import subprocess
import re
import logging
import textwrap
from typing import Optional
from errors import ShadowCopyError

def _run_powershell(command: str, timeout: int = 30) -> str:
    """
    Execute a PowerShell command and return its output.

    This function runs the provided PowerShell command with a specified timeout.
    If the command fails (non-zero exit code) or times out, it raises a ShadowCopyError
    with detailed output.

    Args:
        command (str): The PowerShell command to execute.
        timeout (int): Maximum time (in seconds) to wait for the command to complete.

    Returns:
        str: The output from the PowerShell command.

    Raises:
        ShadowCopyError: If the command exits with a non-zero exit code or times out.
    """
    # Dedent and strip the command for cleaner logging.
    formatted_command = textwrap.dedent(command).strip()
    logging.debug("Executing PowerShell command:\n%s", formatted_command)
    
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=True,
            text=True
        )
        output = result.stdout.strip()
        logging.debug("PowerShell command output:\n%s", output)
        return output
    except subprocess.CalledProcessError as e:
        error_msg = (f"PowerShell command failed with exit code {e.returncode}:\n"
                     f"{e.output}")
        logging.error(error_msg)
        raise ShadowCopyError(error_msg) from e
    except subprocess.TimeoutExpired as e:
        error_msg = f"PowerShell command timed out after {timeout} seconds."
        logging.error(error_msg)
        raise ShadowCopyError(error_msg) from e
    except Exception as e:
        error_msg = f"Unexpected error while running PowerShell command: {e}"
        logging.error(error_msg, exc_info=True)
        raise ShadowCopyError(error_msg) from e

def _parse_ps_keyvalue_output(output: str, key: str) -> Optional[str]:
    """
    Parse PowerShell command output to extract the value corresponding to a key.

    The function expects lines in the format "Key : Value" and searches for the
    specified key in a case-insensitive manner. It returns the associated value
    (with surrounding quotes and braces stripped) if found, or None otherwise.

    Args:
        output (str): The output from a PowerShell command.
        key (str): The key to look for in the output.

    Returns:
        Optional[str]: The value associated with the key, or None if not found.
    """
    logging.debug("Parsing output for key '%s'", key)
    # Regular expression that matches lines like "Key : Value"
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*:\s*(.+)$", re.IGNORECASE)
    
    for line in output.splitlines():
        match = pattern.match(line)
        if match:
            value = match.group(1).strip().strip('"{}')
            logging.debug("Found value for key '%s': %s", key, value)
            return value

    logging.debug("Key '%s' not found in output.", key)
    return None
