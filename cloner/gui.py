import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import os

# Import your updated disk_ops functions/classes
from disk_ops import (
    list_physical_drives_powershell,
    validate_source_destination_powershell,
    DiskVerifier,
    create_shadow_copy,
    clone_disk_with_callback
)

from errors import DiskValidationError, ShadowCopyError


def request_admin():
    """Request admin privileges or do nothing if already elevated."""
    # Placeholder: Implement admin privileges request if needed
    pass


def drive_selector_dialog(parent, drives):
    """
    Toplevel dialog with a Listbox of drives.
    Returns (selected_label, selected_device).
    (None, None) if canceled or no selection.
    """
    top = tk.Toplevel(parent)
    top.title("Select Drive")
    top.resizable(False, False)

    selection = {"label": None, "device": None}

    tk.Label(top, text="Select a drive:").pack(pady=5)

    listbox = tk.Listbox(top, width=50, height=8)
    listbox.pack(padx=10, pady=5)

    for dev, model, size in drives:
        gb_size = size / (1024 ** 3) if size else 0
        display_text = f"{os.path.basename(dev)} ({model} - {gb_size:.1f} GB)"
        listbox.insert(tk.END, display_text)

    def on_ok():
        sel = listbox.curselection()
        if sel:
            index = sel[0]
            selected_drive = drives[index]
            selection["label"] = listbox.get(index)
            selection["device"] = selected_drive[0]
        top.destroy()

    def on_cancel():
        top.destroy()

    btn_frame = tk.Frame(top)
    btn_frame.pack(pady=5)
    tk.Button(btn_frame, text="OK", width=10, command=on_ok).pack(side="left", padx=5)
    tk.Button(btn_frame, text="Cancel", width=10, command=on_cancel).pack(side="right", padx=5)

    top.grab_set()
    parent.wait_window(top)

    return (selection["label"], selection["device"])


class ToggleSwitch(tk.Canvas):
    """
    A simple slider-style toggle switch using a Canvas.
    """
    def __init__(self, master, width=50, height=25, bg_off="#cccccc", bg_on="#4cd137",
                 slider_color="white", command=None, *args, **kwargs):
        super().__init__(master, width=width, height=height, highlightthickness=0, *args, **kwargs)
        self.width = width
        self.height = height
        self.bg_off = bg_off
        self.bg_on = bg_on
        self.slider_color = slider_color
        self.command = command
        self.state = False
        self._draw()
        self.bind("<Button-1>", self._toggle)

    def _draw(self):
        self.delete("all")
        r = self.height // 2
        bg = self.bg_on if self.state else self.bg_off
        self.create_oval(0, 0, self.height, self.height, fill=bg, outline=bg)
        self.create_oval(self.width - self.height, 0, self.width, self.height, fill=bg, outline=bg)
        self.create_rectangle(r, 0, self.width - r, self.height, fill=bg, outline=bg)
        slider_x = self.width - self.height if self.state else 0
        self.create_oval(slider_x, 0, slider_x + self.height, self.height,
                         fill=self.slider_color, outline=self.slider_color)

    def _toggle(self, event):
        self.state = not self.state
        self._draw()
        if self.command:
            self.command(self.state)


class DiskClonerApp:
    """Main Tk application for disk cloning."""
    def __init__(self, root):
        self.root = root
        self.root.title("Python Disk Cloner (Advanced)")
        self.root.minsize(600, 400)

        request_admin()
        self.drives = list_physical_drives_powershell()

        self._init_variables()
        self.create_widgets()
        self._start_drive_refresh()

        self.dark_mode_toggle = ToggleSwitch(self.root, command=self.on_dark_mode_toggle)
        self.dark_mode_toggle.pack(side="top", anchor="ne", padx=10, pady=10)
        self.apply_theme()

    def _init_variables(self):
        self.source_drive_label = tk.StringVar()
        self.source_drive_device = None
        self.dest_drive_label = tk.StringVar()
        self.dest_drive_device = None

        self.shadowcopy_var = tk.BooleanVar(value=False)
        self.verify_after_clone = tk.BooleanVar(value=True)
        self.dark_mode = tk.BooleanVar(value=False)

        self.status_var = tk.StringVar(value="Ready")
        self.progress_var = tk.DoubleVar(value=0.0)
        self.cloning_in_progress = False

    def create_widgets(self):
        container = ttk.Frame(self.root, padding="10")
        container.pack(fill="both", expand=True)

        self._create_drive_selection_frame(container)
        self._create_options_frame(container)
        self._create_progress_frame(container)
        self._create_action_buttons(container)

    def _create_drive_selection_frame(self, parent):
        frame = ttk.LabelFrame(parent, text="Drive Selection", padding="5")
        frame.pack(fill="x", padx=5, pady=5)

        src_frame = ttk.Frame(frame)
        src_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(src_frame, text="Source Drive:").pack(side="left")
        ttk.Entry(src_frame, textvariable=self.source_drive_label,
                  state="readonly", width=50).pack(side="left", padx=5)
        ttk.Button(src_frame, text="Browse", command=self.browse_source).pack(side="left")

        dst_frame = ttk.Frame(frame)
        dst_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(dst_frame, text="Destination Drive:").pack(side="left")
        ttk.Entry(dst_frame, textvariable=self.dest_drive_label,
                  state="readonly", width=50).pack(side="left", padx=5)
        ttk.Button(dst_frame, text="Browse", command=self.browse_destination).pack(side="left")

    def _create_options_frame(self, parent):
        frame = ttk.LabelFrame(parent, text="Options", padding="5")
        frame.pack(fill="x", padx=5, pady=5)

        ttk.Checkbutton(frame, text="Use Volume Shadow Copy",
                        variable=self.shadowcopy_var).pack(anchor="w")
        ttk.Checkbutton(frame, text="Verify after cloning",
                        variable=self.verify_after_clone).pack(anchor="w")

    def _create_progress_frame(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(fill="x", padx=5, pady=5)

        self.status_label = ttk.Label(frame, textvariable=self.status_var)
        self.status_label.pack(side="left")

        self.progress_bar = ttk.Progressbar(frame, variable=self.progress_var,
                                            maximum=100, length=300)
        self.progress_bar.pack(side="right", fill="x", expand=True)

    def _create_action_buttons(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(fill="x", padx=5, pady=5)

        self.clone_button = ttk.Button(frame, text="Start Clone",
                                       command=self.on_clone_clicked)
        self.clone_button.pack(side="right")

        self.refresh_button = ttk.Button(frame, text="Refresh Drives",
                                         command=self.refresh_drives)
        self.refresh_button.pack(side="right", padx=5)

    def _start_drive_refresh(self):
        def refresh():
            if not self.cloning_in_progress:
                self.refresh_drives()
            self.root.after(30000, refresh)
        self.root.after(30000, refresh)

    def refresh_drives(self):
        self.drives = list_physical_drives_powershell()
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

    def validate_clone_operation(self) -> bool:
        if not self.source_drive_device or not self.dest_drive_device:
            messagebox.showerror("Error", "Select both source and destination drives.")
            return False

        if self.source_drive_device.lower() == self.dest_drive_device.lower():
            messagebox.showerror("Error", "Source and destination must be different.")
            return False

        try:
            details = validate_source_destination_powershell(
                self.source_drive_device,
                self.dest_drive_device
            )
        except DiskValidationError as e:
            messagebox.showerror("Validation Error", str(e))
            return False

        if details.get('warnings'):
            warning_msg = "\n".join([
                "The following warnings were detected:",
                "",
                *details['warnings'],
                "",
                "Continue anyway?"
            ])
            if not messagebox.askyesno("Warnings", warning_msg):
                return False

        confirm_msg = (
            f"Source Drive: {self.source_drive_label.get()}\n"
            f"Destination Drive: {self.dest_drive_label.get()}\n\n"
            "ALL DATA ON THE DESTINATION DRIVE WILL BE OVERWRITTEN!\n\n"
            "Are you sure you want to proceed?"
        )
        return messagebox.askyesno("Confirm Clone", confirm_msg)

    def on_clone_clicked(self):
        if self.cloning_in_progress:
            messagebox.showinfo("Busy", "A clone operation is already in progress")
            return

        if not self.validate_clone_operation():
            return

        self.start_clone_operation()

    def start_clone_operation(self):
        src_device = self.source_drive_device

        if self.shadowcopy_var.get():
            vol_letter = simpledialog.askstring(
                "Shadow Copy",
                "Enter volume letter to snapshot (e.g., 'C'):",
                parent=self.root
            )
            if vol_letter:
                try:
                    sc_path = create_shadow_copy(vol_letter)
                    messagebox.showinfo("Shadow Copy Created",
                                        f"Shadow copy at:\n{sc_path}")
                    src_device = sc_path
                except ShadowCopyError as err:
                    if not messagebox.askyesno(
                        "Shadow Copy Failed",
                        f"Shadow copy creation failed:\n{str(err)}\n\n"
                        "Proceed with original source?"
                    ):
                        return

        total_size = 0
        for dev, model, size in self.drives:
            if dev.lower() == self.source_drive_device.lower():
                total_size = size
                break

        self.clone_button.config(state="disabled")
        self.status_var.set("Starting clone operation...")
        self.progress_var.set(0)
        self.cloning_in_progress = True

        threading.Thread(
            target=self.clone_thread,
            args=(src_device, self.dest_drive_device, total_size),
            daemon=True
        ).start()

    def clone_thread(self, src_device: str, dst_device: str, total_size: int):
        def progress_callback(copied: int, total: int):
            percent = (copied / total) * 100 if total else 0
            self.root.after(0, self.update_progress, copied, total, percent)

        def error_callback(msg: str):
            self.root.after(0, self.clone_error, str(msg))

        try:
            clone_disk_with_callback(
                src_device,
                dst_device,
                total_size,
                progress_callback=progress_callback,
                error_callback=error_callback
            )
            self.root.after(0, self.clone_complete)
        except Exception as e:
            error_callback(str(e))

    def update_progress(self, copied_bytes: int, total_size: int, percent: float):
        self.progress_var.set(percent)
        if total_size > 0:
            self.status_var.set(
                f"Cloning... {copied_bytes:,}/{total_size:,} bytes ({percent:.1f}%)"
            )
        else:
            self.status_var.set(f"Cloning... {copied_bytes:,} bytes copied")

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
            if messagebox.askyesno("Clone Complete",
                                   "Cloning done. Proceed with verification?"):
                self.start_verification()
                return

        self.status_var.set("Clone complete")
        self.clone_button.config(state="normal")
        self.progress_var.set(100)
        messagebox.showinfo("Success", "Cloning completed successfully!")

    def start_verification(self):
        """Start the verification process in a separate thread."""
        self.status_var.set("Starting verification...")
        self.progress_var.set(0)

        # Get total size from source drive
        total_size = 0
        for dev, model, size in self.drives:
            if dev.lower() == self.source_drive_device.lower():
                total_size = size
                break

        threading.Thread(
            target=self.verify_thread,
            args=(self.source_drive_device, self.dest_drive_device, total_size),
            daemon=True
        ).start()

    def verify_thread(self, source: str, destination: str, total_size: int):
        """Verify that source and destination drives match."""
        def progress_callback(verified: int, total: int):
            percent = (verified / total) * 100 if total else 0
            self.root.after(0, self.update_verify_progress, verified, total, percent)

        try:
            success, msg, diffs = DiskVerifier.verify_disks(
                source,
                destination,
                total_size,
                progress_callback=progress_callback
            )
            self.root.after(0, self.verify_complete, success, msg, diffs)
        except Exception as e:
            self.root.after(0, self.verify_complete, False, str(e), [])

    def update_verify_progress(self, verified_bytes: int, total_bytes: int, percent: float):
        self.progress_var.set(percent)
        self.status_var.set(
            f"Verifying... {verified_bytes:,}/{total_bytes:,} bytes ({percent:.1f}%)"
        )

    def verify_complete(self, success: bool, message: str, differences: list):
        self.clone_button.config(state="normal")
        if success:
            self.status_var.set("Verification complete - match")
            messagebox.showinfo(
                "Verification Complete",
                "Verification completed. Disks match exactly."
            )
        else:
            self.status_var.set("Verification complete - differences found")
            detail = f"Message: {message}\n\n"
            if differences:
                detail += "First few differences:\n"
                for i, diff in enumerate(differences[:5]):
                    detail += (
                        f"Offset {diff['offset']}: "
                        f"Source={diff['source_sample']}, "
                        f"Dest={diff['dest_sample']}\n"
                    )
                if len(differences) > 5:
                    detail += f"\n...and {len(differences) - 5} more differences"
            messagebox.showerror("Verification Failed", detail)

    def cleanup(self):
        """Cleanup resources before application exit."""
        # Implement any necessary cleanup here.
        # For example, if you are caching persistent handles, ensure they are closed.
        pass

    def on_dark_mode_toggle(self, state: bool):
        """Callback for when the dark mode toggle is switched."""
        self.dark_mode.set(state)
        self.toggle_dark_mode()

    def toggle_dark_mode(self):
        """Toggle between light and dark mode by updating styles."""
        style = ttk.Style()
        if self.dark_mode.get():
            style.theme_use('clam')
            style.configure("TFrame", background="#333333")
            style.configure("TLabel", background="#333333", foreground="white")
            style.configure("TButton", background="#555555", foreground="white")
            style.configure("TEntry", fieldbackground="#555555", foreground="white")
            style.configure("TCheckbutton", background="#333333", foreground="white")
            self.root.configure(bg="#333333")
        else:
            style.theme_use('default')
            style.configure("TFrame", background="SystemButtonFace")
            style.configure("TLabel", background="SystemButtonFace", foreground="black")
            style.configure("TButton", background="SystemButtonFace", foreground="black")
            style.configure("TEntry", fieldbackground="white", foreground="black")
            style.configure("TCheckbutton", background="SystemButtonFace", foreground="black")
            self.root.configure(bg="SystemButtonFace")

    def apply_theme(self):
        """Apply the current theme based on the dark_mode variable."""
        self.toggle_dark_mode()


if __name__ == "__main__":
    root = tk.Tk()
    app = DiskClonerApp(root)
    root.mainloop()