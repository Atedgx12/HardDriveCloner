import os
import time
import json
import queue
import psutil
import hashlib
import logging
import threading
import statistics
import traceback
import collections
from typing import Callable, Optional, Dict, Any
from dataclasses import dataclass, asdict

from .raw_access import normalize_device_path, open_raw_device_fd
from .drive_enumeration import list_physical_drives_powershell
from errors import DeviceAccessError
from constants import GENERIC_READ, GENERIC_WRITE, CHUNK_SIZE
from .partition_expansion import expand_partition
from .sector_info import get_drive_characteristics
from .powershell_helpers import _run_powershell

@dataclass
class CloneStatistics:
    """Statistics for the cloning process."""
    start_time: float = 0.0
    read_speeds: list = None
    write_speeds: list = None
    errors: list = None
    chunk_size_changes: list = None
    total_retries: int = 0

    def __post_init__(self):
        self.start_time = time.time()
        self.read_speeds = []
        self.write_speeds = []
        self.errors = []
        self.chunk_size_changes = []

    def get_statistics(self) -> dict:
        """Return current statistics as a dictionary."""
        return {
            'duration': time.time() - self.start_time,
            'average_read_speed': statistics.mean(self.read_speeds) if self.read_speeds else 0,
            'average_write_speed': statistics.mean(self.write_speeds) if self.write_speeds else 0,
            'error_count': len(self.errors),
            'retry_count': self.total_retries,
            'chunk_size_adjustments': len(self.chunk_size_changes)
        }

class RateLimiter:
    """Simple rate limiter for I/O operations."""
    def __init__(self, max_speed_mbps: Optional[float] = None):
        self.max_speed = max_speed_mbps * 1024 * 1024 / 8 if max_speed_mbps else None
        self.last_check = time.time()
        self.bytes_since_check = 0
        self._lock = threading.Lock()

    def limit(self, bytes_processed: int) -> None:
        if not self.max_speed:
            return
        with self._lock:
            self.bytes_since_check += bytes_processed
            current_time = time.time()
            elapsed = current_time - self.last_check
            if elapsed > 0:
                current_speed = self.bytes_since_check / elapsed
                if current_speed > self.max_speed:
                    sleep_time = self.bytes_since_check / self.max_speed - elapsed
                    if sleep_time > 0:
                        time.sleep(sleep_time)
                self.bytes_since_check = 0
                self.last_check = time.time()

def update_disk_info(timeout: int = 30) -> None:
    """Force Windows to update its disk information."""
    ps_script = "Update-HostStorageCache"
    output = _run_powershell(ps_script, timeout=timeout)
    logging.info("Disk info updated: %s", output)

class AdaptiveCloner:
    """
    An adaptive disk cloner with dynamic buffer sizing, memory buffering,
    and multithreading using a producer/consumer model.
    """
    def __init__(self, source: str, destination: str, total_size: int,
                 flush_threshold: int = 32 * 1024 * 1024,  # Increased flush threshold to 32 MB
                 max_speed_mbps: Optional[float] = None,
                 queue_size: Optional[int] = None):
        self.source = normalize_device_path(source)
        self.destination = normalize_device_path(destination)
        self.total_size = total_size
        self.flush_threshold = flush_threshold

        self.statistics = CloneStatistics()
        self.throughput_history = collections.deque(maxlen=100)
        self.latency_history = collections.deque(maxlen=100)

        self.rate_limiter = RateLimiter(max_speed_mbps)

        try:
            drive_info = get_drive_characteristics(self.source)
            self.sector_size = drive_info['physical_sector_size']
            self.initial_chunk = drive_info['optimal_transfer_size']
            self.is_ssd = drive_info['is_ssd']
            logging.info(f"Source drive: sector_size={self.sector_size}, "
                         f"optimal_transfer_size={self.initial_chunk}, "
                         f"type={'SSD' if self.is_ssd else 'HDD'}")
        except Exception as e:
            logging.warning(f"Failed to get drive characteristics: {e}. Using defaults.")
            self.sector_size = 512
            self.initial_chunk = 1024 * 1024
            self.is_ssd = False

        self.current_chunk = self.initial_chunk
        # Increase default queue size (up to 50) if not specified.
        if queue_size is None:
            mem = psutil.virtual_memory()
            self.queue_size = min(50, max(20, int(mem.available * 0.25 / self.initial_chunk)))
        else:
            self.queue_size = queue_size

        self.data_queue = queue.Queue(maxsize=self.queue_size)
        self.bytes_copied = 0
        self.lock = threading.Lock()
        self.read_error = None
        self.write_error = None

        self.pause_event = threading.Event()
        self.pause_event.set()
        self.checkpoint_lock = threading.Lock()
        self.last_checkpoint = 0

        self.setup_monitoring()

    def setup_monitoring(self) -> None:
        def monitor_thread():
            while True:
                time.sleep(5)
                stats = self.statistics.get_statistics()
                if stats['average_write_speed'] < 5 * 1024 * 1024:
                    logging.warning("Low write performance detected")
                qsize = self.data_queue.qsize()
                if qsize == 0:
                    logging.warning("Queue starvation detected")
                elif qsize == self.queue_size:
                    logging.warning("Queue saturation detected")
        threading.Thread(target=monitor_thread, daemon=True).start()

    def adaptive_buffer_size(self) -> int:
        cpu_percent = psutil.cpu_percent()
        mem_available = psutil.virtual_memory().available
        if cpu_percent > 80 or mem_available < 1024 * 1024 * 1024:
            return self.initial_chunk // 2
        elif cpu_percent < 30 and mem_available > 4 * 1024 * 1024 * 1024:
            return self.initial_chunk * 2
        return self.initial_chunk

    def create_checkpoint(self, offset: int) -> None:
        with self.checkpoint_lock:
            self.last_checkpoint = offset
            checkpoint_data = {
                'offset': offset,
                'timestamp': time.time(),
                'statistics': self.statistics.get_statistics()
            }
            with open('clone_checkpoint.json', 'w') as f:
                json.dump(checkpoint_data, f)

    def pause(self) -> None:
        self.pause_event.clear()
        logging.info("Cloning operation paused")

    def resume(self) -> None:
        self.pause_event.set()
        logging.info("Cloning operation resumed")

    def producer(self) -> None:
        retries = 3
        hasher = hashlib.sha256()
        while retries > 0:
            try:
                fd_src = open_raw_device_fd(self.source, GENERIC_READ)
                offset = 0
                while offset < self.total_size:
                    self.pause_event.wait()
                    chunk_size = self.adaptive_buffer_size()
                    chunk_size = (chunk_size // self.sector_size) * self.sector_size
                    chunk_size = min(chunk_size, self.total_size - offset)
                    if chunk_size <= 0:
                        break
                    t0 = time.time()
                    chunk = os.read(fd_src, chunk_size)
                    dt = time.time() - t0
                    if dt > 0 and chunk:
                        read_speed = len(chunk) / dt
                        self.statistics.read_speeds.append(read_speed)
                        self.throughput_history.append(read_speed)
                        if read_speed > 50 * 1024 * 1024 and self.current_chunk < 64 * 1024 * 1024:
                            self.current_chunk *= 2
                            self.statistics.chunk_size_changes.append({
                                'time': time.time(),
                                'new_size': self.current_chunk,
                                'reason': 'increase'
                            })
                        elif read_speed < 10 * 1024 * 1024 and self.current_chunk > self.sector_size:
                            self.current_chunk = max(self.current_chunk // 2, self.sector_size)
                            self.statistics.chunk_size_changes.append({
                                'time': time.time(),
                                'new_size': self.current_chunk,
                                'reason': 'decrease'
                            })
                    if not chunk:
                        break
                    hasher.update(chunk)
                    checksum = hasher.digest()
                    self.rate_limiter.limit(len(chunk))
                    try:
                        self.data_queue.put((offset, chunk, checksum), timeout=1)
                    except queue.Full:
                        logging.warning("Producer waiting: queue is full at offset %d", offset)
                        continue
                    offset += len(chunk)
                    with self.lock:
                        self.bytes_copied = offset
                    if offset % (100 * 1024 * 1024) == 0:
                        self.create_checkpoint(offset)
                self.data_queue.put(None)
                os.close(fd_src)
                return
            except Exception as e:
                retries -= 1
                self.statistics.total_retries += 1
                self.statistics.errors.append({
                    'time': time.time(),
                    'type': 'read_error',
                    'error': str(e)
                })
                if retries == 0:
                    self.read_error = DeviceAccessError(f"Failed to read after 3 attempts: {e}")
                    self.data_queue.put(None)
                    return
                logging.warning(f"Read error, retrying ({retries} attempts left): {e}")
                time.sleep(1)

    def consumer(self) -> None:
        try:
            fd_dst = open_raw_device_fd(self.destination, GENERIC_WRITE)
            test_block = bytearray(self.sector_size)
            if os.write(fd_dst, test_block) != self.sector_size:
                raise IOError("Initial test write failed")
            last_flush = 0
            while True:
                self.pause_event.wait()
                item = self.data_queue.get()
                if item is None:
                    break
                offset, chunk, checksum = item
                t0 = time.time()
                total_written = 0
                while total_written < len(chunk):
                    written = os.write(fd_dst, chunk[total_written:])
                    if written <= 0:
                        raise IOError("Write returned zero bytes")
                    total_written += written
                    if (offset + total_written - last_flush) >= self.flush_threshold:
                        os.fsync(fd_dst)
                        last_flush = offset + total_written
                dt = time.time() - t0
                if dt > 0:
                    self.statistics.write_speeds.append(total_written / dt)
                with self.lock:
                    self.bytes_copied = offset + total_written
            os.fsync(fd_dst)
            os.close(fd_dst)
        except Exception as e:
            self.write_error = e
            self.statistics.errors.append({
                'time': time.time(),
                'type': 'write_error',
                'error': str(e)
            })

    def verify_clone(self) -> bool:
        verify_chunk_size = 1024 * 1024  # 1MB chunks.
        offset = 0
        try:
            fd_src = open_raw_device_fd(self.source, GENERIC_READ)
            fd_dst = open_raw_device_fd(self.destination, GENERIC_READ)
            while offset < self.total_size:
                src_data = os.read(fd_src, verify_chunk_size)
                dst_data = os.read(fd_dst, verify_chunk_size)
                if src_data != dst_data:
                    logging.error(f"Verification failed at offset {offset}")
                    os.close(fd_src)
                    os.close(fd_dst)
                    return False
                offset += len(src_data)
            os.close(fd_src)
            os.close(fd_dst)
            return True
        except Exception as e:
            logging.error(f"Verification failed with error: {e}")
            return False

    def run(self) -> None:
        prod_thread = threading.Thread(target=self.producer)
        cons_thread = threading.Thread(target=self.consumer)
        prod_thread.start()
        cons_thread.start()
        prod_thread.join()
        cons_thread.join()
        if self.read_error:
            raise self.read_error
        if self.write_error:
            raise self.write_error

def clone_disk_with_callback(source: str,
                             destination: str,
                             total_size: int,
                             progress_callback: Optional[Callable[[int, int], None]] = None,
                             error_callback: Optional[Callable[[str], None]] = None,
                             expand_partition_after: bool = False,
                             destination_volume_letter: Optional[str] = None
                             ) -> None:
    """
    Clone a disk from source to destination using adaptive, buffered I/O and multithreading.
    After cloning, update Windows' disk cache to force the system to recognize the destination.
    
    Args:
        source (str): Source device path (e.g., "\\.\PHYSICALDRIVE0").
        destination (str): Destination device path.
        total_size (int): Total bytes to copy.
        progress_callback (Optional[Callable[[int, int], None]]): Callback with (bytes_copied, total_size).
        error_callback (Optional[Callable[[str], None]]): Callback with an error message.
        expand_partition_after (bool): If True, expand the destination partition after clone.
        destination_volume_letter (Optional[str]): Drive letter for partition expansion.
    """
    start_time = time.time()
    try:
        cloner = AdaptiveCloner(source, destination, total_size)
        cloner.run()
        elapsed = time.time() - start_time
        mb_per_sec = cloner.bytes_copied / elapsed / (1024 * 1024)
        logging.info(f"Clone completed in {elapsed:.2f}s. Copied: {cloner.bytes_copied:,} bytes ({mb_per_sec:.1f} MB/s)")
        if cloner.bytes_copied < total_size:
            logging.warning(f"Expected {total_size:,} bytes but copied {cloner.bytes_copied:,} bytes")
    except Exception as e:
        err_msg = f"Clone failed: {str(e)}\n{traceback.format_exc()}"
        logging.error(err_msg)
        if error_callback:
            error_callback(err_msg)
        raise

    try:
        update_disk_info()
    except Exception as e:
        logging.warning(f"Failed to update disk information: {e}")

    if expand_partition_after and destination_volume_letter:
        try:
            expand_partition(destination_volume_letter)
        except Exception as e:
            logging.error(f"Partition expansion failed: {e}")
