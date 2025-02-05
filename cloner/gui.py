import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import os

# Import your updated disk_ops functions/classes
from disk_ops import (
    list_physical_drives,
    DiskValidator,
    DiskVerifier,
    create_shadow_copy,
    clone_disk_with_callback,
    CHUNK_SIZE
)
from errors import DiskValidationError, ShadowCopyError

def request_admin():
    """Request admin privileges or do nothing if already elevated."""
    # Implementation depends on your environment.
    # Typically you'd check if already elevated, otherwise show a UAC prompt, etc.
    pass

def drive_selector_dialog(parent, drives):
    """Show a dialog to pick from a list of drives. Returns (label, device)."""
    # Example quick dialog: you can customize as needed
    top = tk.Toplevel(parent)
    top.title("Select Drive")
    label_var = tk.StringVar()
    device_var = tk.StringVar()

    def on_ok():
        top.destroy()

    def on_cancel():
        label_var.set("")
        device_var.set("")
        top.destroy()

    tk.Label(top, text="Select a drive:").pack(pady=5)
    listbox = tk.Listbox(top, width=50, height=8)
    listbox.pack(padx=10, pady=5)

    for dev, model, size in drives:
        # Display something like "PhysicalDrive0 (Model - 512GB)"
        gb_size = size / (1024**3) if size else 0
        display_text = f"{os.path.basename(dev)} ({model} - {gb_size:.1f} GB)"
        listbox.insert(tk.END, display_text)

    tk.Button(top, text="OK", command=on_ok).pack(side="left", padx=10, pady=10)
    tk.Button(top, text="Cancel", command=on_cancel).pack(side="right", padx=10, pady=10)

    top.grab_set()
    parent.wait_window(top)

    sel = listbox.curselection()
    if sel:
        index = sel[0]
        selected_drive = drives[index]
        label_str = listbox.get(index)
        device_str = selected_drive[0]
        return (label_str, device_str)
    return (None, None)


class DiskClonerApp:
    """Main Tkinter application for disk cloning."""

    def __init__(self, root):
        self.root = root
        self.root.title("Python Disk Cloner (Advanced)")
        self.root.minsize(600, 400)

        # Request admin privileges
        request_admin()

        self.validator = DiskValidator()
        self.drives = list_physical_drives()

        # Tkinter variables
        self._init_variables()

        # Create GUI
        self.create_widgets()

        # Periodically refresh drive list
        self._start_drive_refresh()

    def _init_variables(self):
        self.source_drive_label = tk.StringVar()
        self.source_drive_device = None
        self.dest_drive_label = tk.StringVar()
        self.dest_drive_device = None

        self.shadowcopy_var = tk.BooleanVar(value=False)
        self.verify_after_clone = tk.BooleanVar(value=True)

        self.status_var = tk.StringVar(value="Ready")
        self.progress_var = tk.DoubleVar(value=0.0)
        self.cloning_in_progress = False

    def create_widgets(self):
        main_container = ttk.Frame(self.root, padding="10")
        main_container.pack(fill="both", expand=True)

        # Drive selection
        self._create_drive_selection_frame(main_container)

        # Options
        self._create_options_frame(main_container)

        # Progress
        self._create_progress_frame(main_container)

        # Actions
        self._create_action_buttons(main_container)

    def _create_drive_selection_frame(self, parent):
        frame = ttk.LabelFrame(parent, text="Drive Selection", padding="5")
        frame.pack(fill="x", padx=5, pady=5)

        # Source
        src_frame = ttk.Frame(frame)
        src_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(src_frame, text="Source Drive:").pack(side="left")
        ttk.Entry(src_frame, textvariable=self.source_drive_label,
                  state="readonly", width=50).pack(side="left", padx=5)
        ttk.Button(src_frame, text="Browse", command=self.browse_source).pack(side="left")

        # Destination
        dst_frame = ttk.Frame(frame)
        dst_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(dst_frame, text="Destination Drive:").pack(side="left")
        ttk.Entry(dst_frame, textvariable=self.dest_drive_label,
                  state="readonly", width=50).pack(side="left", padx=5)
        ttk.Button(dst_frame, text="Browse", command=self.browse_destination).pack(side="left")

    def _create_options_frame(self, parent):
        frame = ttk.LabelFrame(parent, text="Options", padding="5")
        frame.pack(fill="x", padx=5, pady=5)

        ttk.Checkbutton(frame,
                        text="Use Volume Shadow Copy (for locked volumes)",
                        variable=self.shadowcopy_var).pack(anchor="w")

        ttk.Checkbutton(frame,
                        text="Verify after cloning",
                        variable=self.verify_after_clone).pack(anchor="w")

    def _create_progress_frame(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(fill="x", padx=5, pady=5)

        # Status
        self.status_label = ttk.Label(frame, textvariable=self.status_var)
        self.status_label.pack(side="left")

        # Progress bar
        self.progress_bar = ttk.Progressbar(frame,
                                            variable=self.progress_var,
                                            maximum=100,
                                            length=300)
        self.progress_bar.pack(side="right", fill="x", expand=True)

    def _create_action_buttons(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(fill="x", padx=5, pady=5)

        self.clone_button = ttk.Button(frame, text="Start Clone", command=self.on_clone_clicked)
        self.clone_button.pack(side="right")

        self.refresh_button = ttk.Button(frame, text="Refresh Drives", command=self.refresh_drives)
        self.refresh_button.pack(side="right", padx=5)

    def _start_drive_refresh(self):
        """Automatically refresh the drive list every 30 seconds."""
        def refresh():
            if not self.cloning_in_progress:
                self.refresh_drives()
            self.root.after(30000, refresh)  # 30s refresh interval
        self.root.after(30000, refresh)

    def refresh_drives(self):
        self.drives = list_physical_drives()
        if not self.cloning_in_progress:
            self.status_var.set("Drives refreshed")

    def browse_source(self):
        label, device = drive_selector_dialog(self.root, self.drives)
        if label and device:
            self.source_drive_label.set(label)
            self.source_drive_device = device

    def browse_destination(self):
        label, device = drive_selector_dialog(self.root, self.drives)
        if label and device:
            self.dest_drive_label.set(label)
            self.dest_drive_device = device

    def on_clone_clicked(self):
        if self.cloning_in_progress:
            messagebox.showinfo("Busy", "A clone operation is already in progress")
            return

        if not self.validate_clone_operation():
            return

        # Start
        self.start_clone_operation()

    def validate_clone_operation(self) -> bool:
        """Checks GUI selections & calls DiskValidator. Returns True if all is OK."""
        if not self.source_drive_device or not self.dest_drive_device:
            messagebox.showerror("Error", "Please select both source and destination drives.")
            return False

        if self.source_drive_device.lower() == self.dest_drive_device.lower():
            messagebox.showerror("Error", "Source and destination must be different drives.")
            return False

        # Use the updated DiskValidator, which now raises DiskValidationError
        try:
            details = self.validator.validate_source_destination(
                self.source_drive_device,
                self.dest_drive_device
            )
            # 'details' is a dict with keys like 'warnings', 'source_size', etc.
        except DiskValidationError as e:
            messagebox.showerror("Validation Error", str(e))
            return False

        # Check for warnings
        if details['warnings']:
            warning_msg = "\n".join([
                "The following warnings were detected:",
                "",
                *details['warnings'],
                "",
                "Do you want to continue anyway?"
            ])
            if not messagebox.askyesno("Warnings", warning_msg):
                return False

        # Final confirmation
        confirm_msg = (
            f"Source Drive: {self.source_drive_label.get()}\n"
            f"Destination Drive: {self.dest_drive_label.get()}\n\n"
            "WARNING: ALL DATA ON THE DESTINATION DRIVE WILL BE OVERWRITTEN!\n\n"
            "Are you sure you want to proceed?"
        )
        return messagebox.askyesno("Confirm Clone Operation", confirm_msg)

    def start_clone_operation(self):
        """Starts the clone in a background thread."""
        src_device = self.source_drive_device

        # If user opted for a shadow copy, create it now
        if self.shadowcopy_var.get():
            vol_letter = simpledialog.askstring(
                "Shadow Copy",
                "Enter volume letter to snapshot (e.g., 'C'):",
                parent=self.root
            )
            if vol_letter:
                # The *new* create_shadow_copy raises ShadowCopyError on failure
                try:
                    sc_path = create_shadow_copy(vol_letter)
                    messagebox.showinfo("Shadow Copy Created", f"Shadow copy created at:\n{sc_path}")
                    src_device = sc_path
                except ShadowCopyError as err:
                    if not messagebox.askyesno(
                        "Shadow Copy Failed",
                        f"Shadow copy creation failed:\n{str(err)}\n\n"
                        "Do you want to proceed with the original source?"
                    ):
                        return

        # Get total size from known drives
        total_size = 0
        for dev, model, size in self.drives:
            if dev.lower() == self.source_drive_device.lower():
                total_size = size
                break

        self.clone_button.config(state="disabled")
        self.status_var.set("Starting clone operation...")
        self.progress_var.set(0)
        self.cloning_in_progress = True

        # Launch the clone in a separate thread
        threading.Thread(
            target=self.clone_thread,
            args=(src_device, self.dest_drive_device, total_size),
            daemon=True
        ).start()

    def clone_thread(self, src_device: str, dst_device: str, total_size: int):
        """Background thread for cloning; uses callbacks to update GUI."""
        def progress_callback(copied):
            percent = (copied / total_size) * 100 if total_size else 0
            self.root.after(0, self.update_progress, copied, total_size, percent)

        def error_callback(msg):
            self.root.after(0, self.clone_error, msg)

        try:
            clone_disk_with_callback(
                src_device, dst_device, total_size,
                CHUNK_SIZE, progress_callback, error_callback
            )
            # If clone_disk_with_callback succeeds (no exceptions),
            # we call clone_complete in the main thread:
            self.root.after(0, self.clone_complete)
        except Exception as e:
            # If an unexpected exception occurs,
            # we log it via error_callback => clone_error
            error_callback(str(e))

    def update_progress(self, copied_bytes: int, total_size: int, percent: float):
        self.progress_var.set(percent)
        if total_size > 0:
            self.status_var.set(f"Cloning... {copied_bytes}/{total_size} bytes ({percent:.2f}%)")
        else:
            self.status_var.set(f"Cloning... {copied_bytes} bytes copied (unknown total)")

    def clone_error(self, err_msg: str):
        messagebox.showerror("Clone Error", f"An error occurred:\n\n{err_msg}")
        self.clone_button.config(state="normal")
        self.status_var.set("Clone failed")
        self.cloning_in_progress = False

    def clone_complete(self):
        if not self.cloning_in_progress:
            return

        self.cloning_in_progress = False
        if self.verify_after_clone.get():
            if messagebox.askyesno("Clone Complete", "Cloning done. Proceed with verification?"):
                self.start_verification()
                return

        self.status_var.set("Clone complete")
        self.clone_button.config(state="normal")
        self.progress_var.set(100)
        messagebox.showinfo("Success", "Cloning operation completed successfully!")

    def start_verification(self):
        """Starts the verification process in a background thread."""
        self.status_var.set("Starting verification...")
        self.progress_var.set(0)

        threading.Thread(
            target=self.verify_thread,
            args=(self.source_drive_device, self.dest_drive_device),
            daemon=True
        ).start()

    def verify_thread(self, source: str, destination: str):
        """Background thread for verifying disks."""
        def progress_callback(verified: int, total: int):
            percent = (verified / total) * 100 if total else 0
            self.root.after(0, self.update_verify_progress, verified, total, percent)

        # DiskVerifier.verify_disks returns (success, message, differences)
        success, message, differences = DiskVerifier.verify_disks(
            source, destination, CHUNK_SIZE, progress_callback
        )
        self.root.after(0, self.verify_complete, success, message, differences)

    def update_verify_progress(self, verified_bytes: int, total_bytes: int, percent: float):
        self.progress_var.set(percent)
        self.status_var.set(f"Verifying... {verified_bytes}/{total_bytes} bytes ({percent:.2f}%)")

    def verify_complete(self, success: bool, message: str, differences: list):
        self.clone_button.config(state="normal")

        if success:
            self.status_var.set("Verification complete - Disks match")
            messagebox.showinfo("Verification Complete",
                                "Verification completed successfully. The disks match exactly.")
        else:
            self.status_var.set("Verification complete - Differences found")
            detail = f"Message: {message}\n\n"
            if differences:
                detail += "First few differences:\n"
                for i, diff in enumerate(differences[:5]):
                    detail += (
                        f"Offset {diff['offset']}: "
                        f"Source={diff['source_sample']}, Dest={diff['dest_sample']}\n"
                    )
                if len(differences) > 5:
                    detail += f"\n... and {len(differences) - 5} more differences"

            messagebox.showerror("Verification Failed", detail)

    def cleanup(self):
        """Clean up resources if needed."""
        try:
            if hasattr(self, 'validator'):
                del self.validator
        except:
            pass
