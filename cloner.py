import sys
import os
import subprocess
import ctypes
import threading
import time

##############################
# 1) SELF-INSTALL DEPENDENCIES
##############################
def ensure_dependencies():
    """
    Ensures that required Python packages are installed.
    We attempt to install 'tqdm' if missing, but the script won't crash if it fails.
    """
    try:
        import tqdm  # just to check
    except ImportError:
        try:
            print("Installing 'tqdm' package...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "tqdm"])
        except Exception as e:
            print(f"Failed to install 'tqdm'. Error: {e}")

ensure_dependencies()

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None  # We'll gracefully handle if it fails

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog
    tkinter_loaded = True
except ImportError:
    print("Tkinter not found. The GUI will not function.")
    tkinter_loaded = False

##############################
# 2) ADMIN PRIVILEGES HANDLING
##############################
def is_admin():
    """
    Check if running as Administrator on Windows.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def request_admin(root=None):
    """
    Attempt to relaunch with admin privileges. If user cancels, we continue
    but certain operations may fail. We do not forcibly exit if the user says 'No'.
    """
    if not is_admin():
        if root:
            answer = messagebox.askyesno(
                "Administrator Privileges Required",
                "This tool needs Administrator privileges for many operations.\n\n"
                "Click YES to relaunch with a UAC prompt.\n"
                "If you click NO, some operations may fail."
            )
            if not answer:
                return  # user refused admin
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            sys.exit(0)  # new process starts with admin
        except Exception as e:
            if root:
                messagebox.showwarning(
                    "UAC Elevation Failed",
                    f"Failed to relaunch as admin.\nError: {e}\nContinuing without admin..."
                )

##############################
# 3) WMIC DRIVE LIST
##############################
def list_physical_drives():
    """
    Uses WMIC to list physical drives: DeviceID, Model, Size.
    Returns a list of (device_id, model, size_in_bytes).
    Example device_id: '\\\\.\\PhysicalDrive0'
    """
    cmd = 'wmic diskdrive get DeviceID,Model,Size /format:csv'
    try:
        output = subprocess.check_output(cmd, shell=True).decode(errors="ignore")
    except subprocess.CalledProcessError as e:
        print("[ERROR] WMIC call failed:", e)
        return []
    except Exception as ex:
        print("[ERROR] Unexpected WMIC error:", ex)
        return []

    lines = output.strip().splitlines()
    drives = []
    # Skip the header row if present
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split(',')
        if len(parts) < 4:
            continue
        # CSV format: node,DeviceID,Model,Size
        device_id = parts[1].strip()
        model = parts[2].strip()
        size_str = parts[3].strip()
        try:
            size = int(size_str)
        except ValueError:
            size = 0
        drives.append((device_id, model, size))
    return drives

##############################
# 4) VOLUME SHADOW COPY
##############################
def create_shadow_copy(volume_letter):
    """
    Creates a Volume Shadow Copy for 'volume_letter' (e.g. 'C').
    Returns the shadow path (e.g. '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopyX')
    or None if it fails.
    """
    vol = volume_letter.rstrip('\\') + '\\'
    cmd_create = f'wmic shadowcopy call create Volume="{vol}"'
    try:
        output = subprocess.check_output(cmd_create, shell=True).decode(errors="ignore")
    except Exception as e:
        print("[ERROR] Shadow copy creation failed:", e)
        return None

    shadow_id = None
    for line in output.splitlines():
        line = line.strip()
        if "ShadowID" in line:
            # e.g. ShadowID = "{GUID}";
            shadow_id = line.split('=')[1].strip().strip(';').strip('"{}')
            break

    if not shadow_id:
        print("[ERROR] Could not parse shadow ID from wmic output.")
        return None

    cmd_device = f'wmic shadowcopy where ID="{shadow_id}" get DeviceObject /format:list'
    try:
        output2 = subprocess.check_output(cmd_device, shell=True).decode(errors="ignore")
    except Exception as e:
        print("[ERROR] Could not fetch device object for shadow copy:", e)
        return None

    device_object = None
    for line in output2.splitlines():
        line = line.strip()
        if "DeviceObject=" in line:
            device_object = line.split('=')[1].strip()
            break

    if not device_object:
        print("[ERROR] Shadow copy created but DeviceObject not found.")
        return None

    return device_object

##############################
# 5) ADVANCED DISKPART LOGIC
##############################

def get_disk_layout(disk_number):
    """
    Fetch partition layout details for the given disk number using PowerShell or WMIC.
    We return a list of dicts with partition info. Example keys:
      {
        "PartitionNumber": 1,
        "Size": 12345678,
        "Offset": 1048576,
        "Type": "GPT" or "MBR" if we can determine,
        "PartitionType": "Specific partition GUID if GPT"
      }
    If we fail, return an empty list.
    
    NOTE: Real world usage might rely on "Get-Partition" (PowerShell) or direct parsing of disk sector data.
    """
    partitions = []

    # Attempt with PowerShell Get-Partition
    # We can parse JSON output from: Get-Partition -DiskNumber X | ConvertTo-Json
    # This is more flexible than WMIC for GPT vs MBR info
    ps_script = f"Get-Partition -DiskNumber {disk_number} | Select PartitionNumber,Size,Offset,Type,GptType | ConvertTo-Json"
    cmd = ["powershell", "-Command", ps_script]

    try:
        raw_json = subprocess.check_output(cmd, shell=True)
    except Exception as e:
        print("[ERROR] PowerShell Get-Partition call failed:", e)
        return partitions

    import json
    try:
        data = json.loads(raw_json)
        # data may be a dict if there's only one partition, or a list if multiple
        if isinstance(data, dict):
            data = [data]

        for entry in data:
            part_num = entry.get("PartitionNumber")
            size = entry.get("Size", 0)
            offset = entry.get("Offset", 0)
            part_type = entry.get("Type")   # "Basic", "EFI System Partition", etc.
            gpt_type = entry.get("GptType") # Might be a GUID or None if MBR
            # We'll classify a bit
            if gpt_type and "00000000-0000-0000-0000-000000000000" not in gpt_type:
                style = "GPT"
            else:
                style = "MBR"  # or possibly "Unknown"

            partitions.append({
                "PartitionNumber": part_num,
                "Size": size,
                "Offset": offset,
                "Type": style,
                "PartitionType": part_type,
                "GptType": gpt_type
            })
    except json.JSONDecodeError:
        print("[ERROR] Could not parse PowerShell JSON for disk layout.")

    return partitions


def shrink_partition_advanced(disk_number, partition_number, shrink_mb):
    """
    Attempt to shrink a specific partition by 'shrink_mb'.
    We'll do some checks using get_disk_layout to see if it's feasible.
    Return True if it *appears* successful, False otherwise.
    """
    # 1. Gather partition info
    parts = get_disk_layout(disk_number)
    if not parts:
        print("[ERROR] No partition info found; cannot proceed.")
        return False

    # 2. Find the chosen partition
    target_part = None
    for p in parts:
        if p["PartitionNumber"] == partition_number:
            target_part = p
            break

    if not target_part:
        print("[ERROR] Partition not found on disk.")
        return False

    # 3. Basic logic check: Ensure partition is big enough to shrink
    current_size_mb = target_part["Size"] / (1024*1024)
    if shrink_mb > current_size_mb / 2:
        # Arbitrary rule: don't let the user shrink more than half, for safety
        print("[WARN] Trying to shrink more than half the partition size may fail or cause data issues.")
    
    # 4. We'll create a DiskPart script to shrink
    script_lines = [
        f"select disk {disk_number}",
        f"select partition {partition_number}",
        f"shrink desired={shrink_mb}"
    ]

    script_file = "diskpart_shrink.txt"
    with open(script_file, 'w') as f:
        f.write("\n".join(script_lines))

    success = True
    try:
        output = subprocess.check_output(["diskpart", "/s", script_file], shell=True)
        print(output.decode(errors="ignore"))
    except subprocess.CalledProcessError as e:
        print("[ERROR] DiskPart shrink failed:", e.output)
        success = False
    except Exception as ex:
        print("[ERROR] Unexpected error during shrink:", ex)
        success = False
    finally:
        if os.path.exists(script_file):
            os.remove(script_file)
    return success


def extend_partition_advanced(disk_number, partition_number, extend_mb):
    """
    Attempt to extend a specific partition by 'extend_mb'.
    Return True if success, False otherwise.
    """
    # 1. Gather partition info
    parts = get_disk_layout(disk_number)
    if not parts:
        print("[ERROR] No partition info found; cannot proceed.")
        return False

    # 2. Find the chosen partition
    target_part = None
    for p in parts:
        if p["PartitionNumber"] == partition_number:
            target_part = p
            break

    if not target_part:
        print("[ERROR] Partition not found on disk.")
        return False

    # 3. We don't check free space explicitly here (would require more advanced logic).
    # 4. Construct DiskPart script
    script_lines = [
        f"select disk {disk_number}",
        f"select partition {partition_number}",
        f"extend size={extend_mb}"
    ]

    script_file = "diskpart_extend.txt"
    with open(script_file, 'w') as f:
        f.write("\n".join(script_lines))

    success = True
    try:
        output = subprocess.check_output(["diskpart", "/s", script_file], shell=True)
        print(output.decode(errors="ignore"))
    except subprocess.CalledProcessError as e:
        print("[ERROR] DiskPart extend failed:", e.output)
        success = False
    except Exception as ex:
        print("[ERROR] Unexpected error during extend:", ex)
        success = False
    finally:
        if os.path.exists(script_file):
            os.remove(script_file)
    return success


##############################
# 6) RAW DISK CLONING
##############################
def clone_disk_with_callback(source, destination, total_size, chunk_size, progress_callback, error_callback):
    """
    Clone 'source' to 'destination' in chunks, calling 'progress_callback(copied_bytes)' for progress,
    or 'error_callback(msg)' if an error occurs. We do not force program exit on errors.
    """
    bytes_copied = 0
    try:
        with open(source, 'rb', buffering=0) as src, open(destination, 'wb', buffering=0) as dst:
            while True:
                chunk = src.read(chunk_size)
                if not chunk:
                    break
                dst.write(chunk)
                bytes_copied += len(chunk)
                progress_callback(bytes_copied)
    except Exception as e:
        error_callback(str(e))

##############################
# 7) TKINTER GUI APPLICATION
##############################
if tkinter_loaded:
    class DiskClonerApp:
        def __init__(self, root):
            self.root = root
            self.root.title("Python Disk Cloner (Advanced DiskPart Example)")

            # Attempt admin request (non-fatal if user refuses)
            request_admin(root)

            # Gather drives
            self.drives = list_physical_drives()

            # GUI state
            self.source_var = tk.StringVar()
            self.dest_var = tk.StringVar()
            self.shadowcopy_var = tk.BooleanVar(value=False)

            # Advanced resize partition controls
            self.adv_resize_var = tk.BooleanVar(value=False)
            self.resize_mode_var = tk.StringVar(value="shrink")  # or "extend"
            self.disk_number_var = tk.StringVar()    # which disk we target
            self.partition_number_var = tk.StringVar()
            self.size_mb_var = tk.StringVar()        # how many MB to shrink/extend

            # Status
            self.status_var = tk.StringVar(value="Ready")
            self.progress_var = tk.DoubleVar(value=0.0)
            self.cloning_in_progress = False

            self.create_widgets()
            self.populate_drive_lists()

        def create_widgets(self):
            # Frame for drive selection
            f_drives = ttk.LabelFrame(self.root, text="Select Drives")
            f_drives.pack(fill='x', padx=10, pady=5)

            ttk.Label(f_drives, text="Source Drive:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
            self.source_combo = ttk.Combobox(f_drives, textvariable=self.source_var, width=50)
            self.source_combo.grid(row=0, column=1, padx=5, pady=5, sticky='w')

            ttk.Label(f_drives, text="Destination Drive:").grid(row=1, column=0, padx=5, pady=5, sticky='e')
            self.dest_combo = ttk.Combobox(f_drives, textvariable=self.dest_var, width=50)
            self.dest_combo.grid(row=1, column=1, padx=5, pady=5, sticky='w')

            self.shadow_check = ttk.Checkbutton(
                f_drives,
                text="Use Volume Shadow Copy (for locked files)?",
                variable=self.shadowcopy_var
            )
            self.shadow_check.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky='w')

            # Frame for advanced DiskPart
            f_adv = ttk.LabelFrame(self.root, text="Advanced DiskPart (Optional)")
            f_adv.pack(fill='x', padx=10, pady=5)

            self.adv_check = ttk.Checkbutton(
                f_adv, text="Use Advanced Partition Resize?", variable=self.adv_resize_var
            )
            self.adv_check.grid(row=0, column=0, columnspan=2, sticky='w', padx=5, pady=5)

            # Resize mode: shrink or extend
            mode_frame = ttk.Frame(f_adv)
            mode_frame.grid(row=1, column=0, columnspan=2, sticky='w', padx=5, pady=5)
            self.rb_shrink = ttk.Radiobutton(
                mode_frame, text="Shrink", variable=self.resize_mode_var, value="shrink"
            )
            self.rb_extend = ttk.Radiobutton(
                mode_frame, text="Extend", variable=self.resize_mode_var, value="extend"
            )
            self.rb_shrink.pack(side='left')
            self.rb_extend.pack(side='left')

            ttk.Label(f_adv, text="Disk # (e.g. 0):").grid(row=2, column=0, sticky='e', padx=5, pady=5)
            ttk.Entry(f_adv, textvariable=self.disk_number_var, width=10).grid(row=2, column=1, sticky='w', padx=5, pady=5)

            ttk.Label(f_adv, text="Partition # (e.g. 1):").grid(row=3, column=0, sticky='e', padx=5, pady=5)
            ttk.Entry(f_adv, textvariable=self.partition_number_var, width=10).grid(row=3, column=1, sticky='w', padx=5, pady=5)

            ttk.Label(f_adv, text="MB to Shrink/Extend (e.g. 5000):").grid(row=4, column=0, sticky='e', padx=5, pady=5)
            ttk.Entry(f_adv, textvariable=self.size_mb_var, width=10).grid(row=4, column=1, sticky='w', padx=5, pady=5)

            # Frame for status
            f_status = ttk.Frame(self.root)
            f_status.pack(fill='x', padx=10, pady=5)

            self.status_label = ttk.Label(f_status, textvariable=self.status_var)
            self.status_label.pack(side='left', padx=5)

            self.progress_bar = ttk.Progressbar(f_status, variable=self.progress_var, maximum=100)
            self.progress_bar.pack(side='right', fill='x', expand=True, padx=5)

            # Action frame
            f_actions = ttk.Frame(self.root)
            f_actions.pack(fill='x', padx=10, pady=5)

            self.clone_button = ttk.Button(f_actions, text="Clone", command=self.on_clone_clicked)
            self.clone_button.pack(side='right', padx=5)

        def populate_drive_lists(self):
            drive_labels = []
            for dev, model, size in self.drives:
                gb_size = size / (1024**3) if size else 0
                label = f"{dev} | {model} | {gb_size:.2f} GB"
                drive_labels.append(label)

            if drive_labels:
                self.source_combo['values'] = drive_labels
                self.dest_combo['values'] = drive_labels
            else:
                self.source_combo['values'] = ["No drives found"]
                self.dest_combo['values'] = ["No drives found"]

        def on_clone_clicked(self):
            if self.cloning_in_progress:
                messagebox.showinfo("Cloning", "A clone is already in progress. Please wait.")
                return

            src_label = self.source_var.get()
            dst_label = self.dest_var.get()
            if not src_label or not dst_label:
                messagebox.showerror("Error", "Please select source and destination drives.")
                return
            if "No drives found" in src_label or "No drives found" in dst_label:
                messagebox.showerror("Error", "No valid drives found. Cannot proceed.")
                return
            if src_label == dst_label:
                messagebox.showerror("Error", "Source and destination must be different.")
                return

            src_device = src_label.split('|')[0].strip()
            dst_device = dst_label.split('|')[0].strip()

            confirm = messagebox.askyesno(
                "Confirm",
                f"Are you sure you want to clone?\n\nSource: {src_device}\nDestination: {dst_device}\n"
                "All data on destination will be overwritten!"
            )
            if not confirm:
                return

            # Handle Volume Shadow Copy
            if self.shadowcopy_var.get():
                vol_letter = simpledialog.askstring("Shadow Copy", "Enter volume letter to snapshot (e.g. C):", parent=self.root)
                if vol_letter:
                    sc_path = create_shadow_copy(vol_letter)
                    if sc_path:
                        messagebox.showinfo("Shadow Copy Created", f"Shadow copy created at:\n{sc_path}")
                        src_device = sc_path
                    else:
                        messagebox.showwarning("Failed", "Shadow copy creation failed. Proceeding with original source.")
                else:
                    messagebox.showinfo("No Volume", "No volume letter specified. Proceeding without shadow copy.")

            # Handle advanced DiskPart logic
            if self.adv_resize_var.get():
                disk_no_str = self.disk_number_var.get()
                part_no_str = self.partition_number_var.get()
                size_mb_str = self.size_mb_var.get()
                mode = self.resize_mode_var.get()  # "shrink" or "extend"

                if disk_no_str and part_no_str and size_mb_str:
                    try:
                        disk_no = int(disk_no_str)
                        part_no = int(part_no_str)
                        size_mb = int(size_mb_str)
                    except ValueError:
                        messagebox.showerror("Error", "Disk #, Partition #, and Size must be valid integers.")
                    else:
                        if mode == "shrink":
                            success = shrink_partition_advanced(disk_no, part_no, size_mb)
                            if not success:
                                messagebox.showwarning("Failed", "Partition shrink failed. Check console for details.")
                        else:
                            success = extend_partition_advanced(disk_no, part_no, size_mb)
                            if not success:
                                messagebox.showwarning("Failed", "Partition extend failed. Check console for details.")
                else:
                    messagebox.showinfo("Skipping", "Partition resize not performed (missing or invalid inputs).")

            # Find total size for progress
            total_size = 0
            for (dev, model, size) in self.drives:
                if dev.lower() == src_device.lower():
                    total_size = size
                    break

            self.clone_button.config(state='disabled')
            self.status_var.set("Cloning in progress...")
            self.progress_var.set(0)
            self.cloning_in_progress = True

            # Start thread
            th = threading.Thread(target=self.clone_thread, args=(src_device, dst_device, total_size))
            th.start()

        def clone_thread(self, src_device, dst_device, total_size):
            chunk_size = 1024 * 1024  # 1 MB

            def progress_callback(copied):
                if total_size > 0:
                    percent = (copied / total_size) * 100
                else:
                    percent = 0
                self.root.after(0, self.update_progress, copied, total_size, percent)

            def error_callback(msg):
                self.root.after(0, self.clone_error, msg)

            clone_disk_with_callback(
                src_device, 
                dst_device, 
                total_size, 
                chunk_size, 
                progress_callback, 
                error_callback
            )
            self.root.after(0, self.clone_complete)

        def update_progress(self, copied_bytes, total_size, percent):
            self.progress_var.set(percent)
            if total_size > 0:
                self.status_var.set(f"Cloning... {copied_bytes}/{total_size} bytes ({percent:.2f}%)")
            else:
                self.status_var.set(f"Cloning... {copied_bytes} bytes copied (unknown total)")

        def clone_error(self, err_msg):
            messagebox.showerror("Clone Error", f"An error occurred:\n\n{err_msg}")
            self.clone_button.config(state='normal')
            self.status_var.set("Clone failed.")
            self.cloning_in_progress = False

        def clone_complete(self):
            if not self.cloning_in_progress:
                # Means we had an error
                return
            self.cloning_in_progress = False
            self.status_var.set("Clone complete.")
            self.clone_button.config(state='normal')
            self.progress_var.set(100)
            messagebox.showinfo("Done", "Cloning operation finished successfully!")

    def main():
        root = tk.Tk()
        app = DiskClonerApp(root)
        root.mainloop()

    if __name__ == "__main__":
        main()

else:
    # If tkinter is not available, we won't forcibly exit, but we can't show a GUI.
    print("Tkinter not available. No GUI can be displayed. Exiting gracefully.")
