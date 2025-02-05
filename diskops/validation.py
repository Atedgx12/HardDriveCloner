from typing import Dict, Any, List, Tuple
import logging
from .drive_enumeration import list_physical_drives_powershell
from errors import DiskValidationError

def validate_source_destination_powershell(source: str, destination: str) -> Dict[str, Any]:
    """
    Validate that the source and destination drives are suitable for cloning.

    This function verifies that:
      - The source and destination drives are not the same.
      - Both drives exist and have a nonzero size.
      - The destination drive is at least as large as the source drive.

    Args:
        source (str): The source device identifier (e.g., "\\.\PHYSICALDRIVE8").
        destination (str): The destination device identifier (e.g., "\\.\PHYSICALDRIVE6").

    Returns:
        Dict[str, Any]: A dictionary with the following keys:
            - 'source_size': int, the size of the source drive in bytes.
            - 'dest_size': int, the size of the destination drive in bytes.
            - 'warnings': List[str], a list for any warnings (empty if none).
            - 'source_volumes': List[Any], a placeholder for source volumes.
            - 'dest_volumes': List[Any], a placeholder for destination volumes.

    Raises:
        DiskValidationError: If any of the validation checks fail.
    """
    # Normalize drive identifiers for case-insensitive comparison.
    source_key = source.lower()
    destination_key = destination.lower()

    # Ensure the source and destination are not the same.
    if source_key == destination_key:
        raise DiskValidationError("Source and destination cannot be the same drive.")

    # Retrieve all available drives with nonzero size.
    all_drives: List[Tuple[str, str, int]] = list_physical_drives_powershell()
    drive_map: Dict[str, Tuple[str, int]] = {
        dev_id.lower(): (model, size) for (dev_id, model, size) in all_drives if size > 0
    }

    # Check that both source and destination drives exist in the drive map.
    if source_key not in drive_map:
        raise DiskValidationError(f"Source drive not found or has an invalid size: {source}")
    if destination_key not in drive_map:
        raise DiskValidationError(f"Destination drive not found or has an invalid size: {destination}")

    source_model, source_size = drive_map[source_key]
    dest_model, dest_size = drive_map[destination_key]

    logging.debug(
        "Validated drives - Source: %s (Size: %d bytes), Destination: %s (Size: %d bytes)",
        source_model, source_size, dest_model, dest_size
    )

    # Ensure that the destination drive is large enough.
    if dest_size < source_size:
        raise DiskValidationError(
            f"Destination too small.\n"
            f"Source: {source_size / (1024**3):.2f} GB\n"
            f"Destination: {dest_size / (1024**3):.2f} GB"
        )

    # Return a dictionary with the validated sizes and placeholders for future extensions.
    return {
        'source_size': source_size,
        'dest_size': dest_size,
        'warnings': [],
        'source_volumes': [],
        'dest_volumes': []
    }
