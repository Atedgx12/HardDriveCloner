import os
import logging
import traceback
from typing import Callable, Optional, Dict, Any, List, Tuple
from .raw_access import open_raw_device_fd
from constants import CHUNK_SIZE, GENERIC_READ, GENERIC_WRITE

class DiskVerifier:
    @staticmethod
    def verify_disks(source: str,
                     destination: str,
                     total_size: int,
                     chunk_size: int = CHUNK_SIZE,
                     progress_callback: Optional[Callable[[int, int], None]] = None
                     ) -> Tuple[bool, str, List[Dict[str, Any]]]:
        """
        Compare the contents of two disks by reading and comparing data in chunks.

        This method opens the source and destination devices in raw mode,
        reads data in chunks from the source, and compares it against the data
        read from the destination. If any differences are found, they are recorded
        and returned in the result tuple. If an error occurs during the verification
        process, a detailed error message is logged and returned.

        Args:
            source (str): The source device identifier (e.g., "\\.\PHYSICALDRIVE8").
            destination (str): The destination device identifier (e.g., "\\.\PHYSICALDRIVE6").
            total_size (int): The total number of bytes to verify.
            chunk_size (int): The number of bytes to read per iteration (default is CHUNK_SIZE).
            progress_callback (Optional[Callable[[int, int], None]]): Optional callback to report progress.
                Receives two arguments: the number of bytes verified so far and the total size.

        Returns:
            Tuple[bool, str, List[Dict[str, Any]]]: A tuple where:
                - The first element is a boolean indicating whether the disks match exactly.
                - The second element is a descriptive message.
                - The third element is a list of dictionaries detailing differences (if any).

        Raises:
            Exception: Propagates any unexpected exceptions encountered during the process.
        """
        # Validate inputs.
        if not isinstance(total_size, int) or total_size <= 0:
            raise ValueError("total_size must be a positive integer")
        if not isinstance(chunk_size, int) or chunk_size <= 0:
            raise ValueError("chunk_size must be a positive integer")

        differences: List[Dict[str, Any]] = []
        bytes_verified = 0
        fd_src = None
        fd_dst = None

        logging.debug("Starting disk verification: total_size=%d, chunk_size=%d", total_size, chunk_size)

        try:
            # Open source and destination devices in raw mode.
            fd_src = open_raw_device_fd(source, GENERIC_READ)
            fd_dst = open_raw_device_fd(destination, GENERIC_READ)
            logging.debug("Opened source fd: %d, destination fd: %d", fd_src, fd_dst)

            while bytes_verified < total_size:
                try:
                    # Read a chunk from the source device.
                    chunk_src = os.read(fd_src, chunk_size)
                except Exception as e:
                    raise IOError(f"Error reading from source device at offset {bytes_verified}: {e}")

                if not chunk_src:
                    logging.debug("No more data from source at offset %d; ending verification.", bytes_verified)
                    break

                try:
                    # Read the same amount of data from the destination device.
                    chunk_dst = os.read(fd_dst, len(chunk_src))
                except Exception as e:
                    raise IOError(f"Error reading from destination device at offset {bytes_verified}: {e}")

                # Compare the chunks. If they differ, record the difference.
                if chunk_src != chunk_dst:
                    diff_info = {
                        'offset': bytes_verified,
                        'length': len(chunk_src),
                        'source_sample': chunk_src[:16].hex(),
                        'dest_sample': chunk_dst[:16].hex() if chunk_dst else 'No data'
                    }
                    differences.append(diff_info)
                    logging.debug("Difference detected at offset %d: %s", bytes_verified, diff_info)

                bytes_verified += len(chunk_src)

                # Report progress if a callback is provided.
                if progress_callback and callable(progress_callback):
                    try:
                        progress_callback(bytes_verified, total_size)
                    except Exception as cb_exc:
                        logging.warning("Progress callback error at offset %d: %s", bytes_verified, cb_exc)

            logging.info("Verification completed: %d bytes verified out of %d", bytes_verified, total_size)

        except Exception as e:
            msg = f"Verification failed: {e}"
            logging.error(msg, exc_info=True)
            return (False, msg, differences)
        finally:
            # Ensure file descriptors are closed properly.
            if fd_src is not None:
                try:
                    os.close(fd_src)
                    logging.debug("Closed source fd: %d", fd_src)
                except Exception as e:
                    logging.error("Error closing source fd: %s", e)
            if fd_dst is not None:
                try:
                    os.close(fd_dst)
                    logging.debug("Closed destination fd: %d", fd_dst)
                except Exception as e:
                    logging.error("Error closing destination fd: %s", e)

        if differences:
            msg = f"Found {len(differences)} differences"
            logging.warning(msg)
            return (False, msg, differences)

        success_msg = "Verification successful - disks match exactly"
        logging.info(success_msg)
        return (True, success_msg, [])
