import os
import time
import logging
import traceback
from typing import Callable, Optional
from .raw_access import normalize_device_path, open_raw_device_fd, RawDevice
from .drive_enumeration import list_physical_drives_powershell
from errors import DeviceAccessError
from constants import GENERIC_READ, GENERIC_WRITE
from .partition_expansion import expand_partition
from .sector_info import get_drive_characteristics

def clone_disk_with_callback(source: str,
                           destination: str,
                           total_size: int,
                           progress_callback: Optional[Callable[[int, int], None]] = None,
                           error_callback: Optional[Callable[[str], None]] = None,
                           expand_partition_after: bool = False,
                           destination_volume_letter: Optional[str] = None
                           ) -> None:
    """
    Clone a disk from source to destination using optimal drive settings.
    
    Args:
        source: Source device path (e.g., "\\.\PHYSICALDRIVE0")
        destination: Destination device path
        total_size: Total bytes to copy
        progress_callback: Optional function taking (copied_bytes, total_bytes)
        error_callback: Optional function taking (error_message)
        expand_partition_after: Whether to expand dest partition after clone
        destination_volume_letter: Drive letter for partition expansion
    """
    bytes_copied = 0
    start_time = time.time()

    def report_progress(current_bytes: int) -> None:
        """Report progress via callback if available."""
        if callable(progress_callback):
            try:
                progress_callback(current_bytes, total_size)
            except Exception as e:
                logging.error(f"Progress callback error: {e}", exc_info=True)

    def report_error(error_msg: str) -> None:
        """Report error via callback if available."""
        if callable(error_callback):
            try:
                error_callback(str(error_msg))
            except Exception as e:
                logging.error(f"Error callback failed: {e}", exc_info=True)

    try:
        source = normalize_device_path(source)
        destination = normalize_device_path(destination)
        
        try:
            drive_info = get_drive_characteristics(source)
            source_sector_size = drive_info['physical_sector_size']
            alignment_offset = drive_info['alignment_offset']
            chunk_size = drive_info['optimal_transfer_size']
            is_ssd = drive_info['is_ssd']
            
            logging.info(
                f"Source drive: sector_size={source_sector_size}, "
                f"alignment={alignment_offset}, "
                f"transfer_size={chunk_size}, "
                f"type={'SSD' if is_ssd else 'HDD'}"
            )
        except Exception as e:
            logging.warning(f"Failed to get drive characteristics: {e}. Using defaults.")
            source_sector_size = 512
            alignment_offset = 0
            chunk_size = 1024 * 1024  # 1MB fallback
            is_ssd = False

        drives = list_physical_drives_powershell()
        drive_paths = {d[0].lower() for d in drives}
        for dev in (source, destination):
            if dev.lower() not in drive_paths:
                raise DeviceAccessError(f"Device not found: {dev}")

        with RawDevice(source, GENERIC_READ) as fd_src:
            fd_dst = None
            try:
                fd_dst = open_raw_device_fd(destination, GENERIC_WRITE)
                
                # Verify destination is writable
                test_block = bytearray(source_sector_size)
                if os.write(fd_dst, test_block) != source_sector_size:
                    raise IOError("Initial test write failed")

                while bytes_copied < total_size:
                    # Calculate aligned read size
                    to_read = min(chunk_size, total_size - bytes_copied)
                    if alignment_offset:
                        to_read = to_read - ((to_read + alignment_offset) % source_sector_size)
                    else:
                        to_read = to_read - (to_read % source_sector_size)
                    
                    try:
                        chunk_data = os.read(fd_src, to_read)
                    except Exception as e:
                        raise IOError(f"Read error: {e}")

                    if not chunk_data:
                        break

                    write_success = False
                    retry_count = 0
                    current_offset = bytes_copied
                    total_written = 0

                    while not write_success and retry_count < 3:
                        try:
                            while total_written < len(chunk_data):
                                remaining_data = chunk_data[total_written:]
                                written = os.write(fd_dst, remaining_data)
                                if written == 0:
                                    time.sleep(0.1)
                                    continue
                                
                                total_written += written
                                
                                # Periodic flush
                                flush_size = 8 * 1024 * 1024 if is_ssd else 1024 * 1024
                                if total_written % flush_size == 0:
                                    try:
                                        os.fsync(fd_dst)
                                    except OSError:
                                        pass
                                    
                            write_success = True

                        except OSError as e:
                            if e.errno == 9:  # Bad file descriptor
                                retry_count += 1
                                if retry_count >= 3:
                                    raise IOError("Maximum write retries exceeded")
                                    
                                logging.warning(f"Retrying write (attempt {retry_count}/3)")
                                
                                try:
                                    os.close(fd_dst)
                                except Exception:
                                    pass
                                    
                                delay = retry_count * (0.2 if is_ssd else 1.0)
                                time.sleep(delay)
                                
                                try:
                                    fd_dst = open_raw_device_fd(destination, GENERIC_WRITE)
                                    test_written = os.write(fd_dst, bytearray(source_sector_size))
                                    if test_written != source_sector_size:
                                        raise IOError(f"Test write after reopen failed")
                                        
                                    os.lseek(fd_dst, current_offset + total_written, os.SEEK_SET)
                                except Exception as reopen_error:
                                    raise IOError(f"Failed to reopen destination: {reopen_error}")
                            else:
                                raise

                    bytes_copied += len(chunk_data)
                    report_progress(bytes_copied)

                # Ensure all data is written
                os.fsync(fd_dst)
                
                elapsed = time.time() - start_time
                mb_per_sec = bytes_copied / elapsed / 1024 / 1024  # MB/s
                logging.info(
                    f"Clone completed in {elapsed:.2f}s. "
                    f"Copied: {bytes_copied:,} bytes "
                    f"({mb_per_sec:.1f} MB/s)"
                )
                
                if bytes_copied < total_size:
                    logging.warning(
                        f"Expected {total_size:,} bytes "
                        f"but copied {bytes_copied:,} bytes"
                    )

            finally:
                if fd_dst is not None:
                    try:
                        os.close(fd_dst)
                    except Exception as e:
                        logging.error(f"Error closing destination: {e}")

    except Exception as e:
        error_msg = f"Clone failed: {str(e)}\nTrace:\n{traceback.format_exc()}"
        logging.error(error_msg)
        report_error(error_msg)
        raise

    if expand_partition_after and destination_volume_letter:
        try:
            expand_partition(destination_volume_letter)
        except Exception as e:
            logging.error(f"Partition expansion failed: {e}")