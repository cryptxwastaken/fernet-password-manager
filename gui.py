from os.path import exists
from pathlib import Path
from tkinter import messagebox

import customtkinter as ctk
import pyperclip
from cryptography.fernet import InvalidToken

import project
from project import (
    add_entry,
    create_pass,
    ensure_credentials_dirs,
    get_default_vault,
    init_salt,
    list_vaults,
    search_entries,
    set_default_vault,
    verify_master_password,
)

ICON_PATH = Path(__file__).resolve().parent / "assets" / "icon.ico"


def apply_window_icon(window: ctk.CTk | ctk.CTkToplevel) -> None:
    if ICON_PATH.exists():
        window.iconbitmap(default=str(ICON_PATH))


class PasswordManagerApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Fernet Password Manager")
        self.geometry("640x520")
        self._set_window_icon()
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        # App state (set after a successful unlock).
        self.master_key: bytes | None = None
        self.vault_name: str | None = None
        # Rows currently shown in the list: (vault_index, site_name, password).
        self.visible_entries: list[tuple[int, str, str]] = []

        ensure_credentials_dirs()
        init_salt()

        # One big frame holds whichever screen is active (unlock or main).
        self.screen = ctk.CTkFrame(self)
        self.screen.pack(fill="both", expand=True, padx=16, pady=16)

        self.show_unlock_screen()

    def _set_window_icon(self) -> None:
        apply_window_icon(self)

    def clear_screen(self) -> None:
        # Remove all widgets so we can draw a fresh screen.
        for widget in self.screen.winfo_children():
            widget.destroy()

    def show_unlock_screen(self) -> None:
        self.clear_screen()
        self.master_key = None

        ctk.CTkLabel(self.screen, text="Unlock a Vault", font=("", 22, "bold")).pack(pady=(32, 16))

        vaults = list_vaults()
        self.vault_var = ctk.StringVar(value=get_default_vault() or (vaults[0] if vaults else ""))
        self.vault_menu = ctk.CTkOptionMenu(
            self.screen,
            values=vaults if vaults else ["No vaults yet"],
            variable=self.vault_var,
            width=280,
        )
        self.vault_menu.pack(pady=8)

        # command= runs create_vault_dialog when the button is clicked.
        ctk.CTkButton(self.screen, text="Create vault", command=self.create_vault_dialog).pack(
            pady=8
        )

        self.password_entry = ctk.CTkEntry(
            self.screen, show="*", width=280, placeholder_text="Master password"
        )
        self.password_entry.pack(pady=(36, 8))
        # bind: pressing Enter in the password box also unlocks.
        self.password_entry.bind("<Return>", lambda _event: self.unlock())

        ctk.CTkButton(self.screen, text="Unlock", command=self.unlock).pack(pady=8)

    def create_vault_dialog(self) -> None:
        dialog = ctk.CTkInputDialog(text="Vault name:", title="Create vault")
        name = dialog.get_input()
        if not name:
            return
        result = create_pass(name.strip())
        if result.startswith("Successfully"):
            messagebox.showinfo("Success", result)
            self.show_unlock_screen()
        else:
            messagebox.showerror("Error", result)

    def unlock(self) -> None:
        vault_name = self.vault_var.get().strip()
        if vault_name == "" or vault_name == "No vaults yet":
            messagebox.showerror("Error", "Create a vault first.")
            return
        if not exists(project.vault_path(vault_name)):
            messagebox.showerror("Error", "The password file doesn't exist!")
            return

        master_password = self.password_entry.get()
        try:
            self.master_key = verify_master_password(master_password, vault_name)
        except (InvalidToken, FileNotFoundError) as exc:
            messagebox.showerror("Error", str(exc))
            return

        self.vault_name = vault_name
        set_default_vault(vault_name)
        self.show_main_screen()

    def show_main_screen(self) -> None:
        if self.master_key is None or self.vault_name is None:
            self.show_unlock_screen()
            return

        self.clear_screen()
        ctk.CTkLabel(
            self.screen,
            text=f"Vault: {self.vault_name}",
            font=("", 18, "bold"),
        ).pack(pady=(8, 8))

        toolbar = ctk.CTkFrame(self.screen)
        toolbar.pack(fill="x", pady=4)
        ctk.CTkButton(toolbar, text="Add", width=80, command=self.add_entry_dialog).pack(
            side="left", padx=4
        )
        ctk.CTkButton(toolbar, text="Lock", width=80, command=self.show_unlock_screen).pack(
            side="right", padx=4
        )

        self.search_entry = ctk.CTkEntry(self.screen, placeholder_text="Search sites...", width=400)
        self.search_entry.pack(pady=(24, 4))
        # Refresh the list on every key release while searching.
        self.search_entry.bind("<KeyRelease>", lambda _event: self.refresh_list())

        # Empty label for status messages (e.g. "Password copied to clipboard.").
        self.status_label = ctk.CTkLabel(self.screen, text="")
        self.status_label.pack(pady=4)

        self.list_frame = ctk.CTkScrollableFrame(self.screen, width=560, height=300)
        self.list_frame.pack(fill="both", expand=True, pady=8)

        self.refresh_list()

    def refresh_list(self) -> None:
        if self.master_key is None or self.vault_name is None:
            return

        query = self.search_entry.get() if hasattr(self, "search_entry") else ""
        try:
            self.visible_entries = search_entries(self.vault_name, self.master_key, query)
        except FileNotFoundError as exc:
            messagebox.showerror("Error", str(exc))
            return

        # Delete old rows on screen.
        for widget in self.list_frame.winfo_children():
            widget.destroy()

        if not self.visible_entries:
            ctk.CTkLabel(self.list_frame, text="No matching entries.").pack(pady=8)
            return

        for index, site, _password in self.visible_entries:
            row = ctk.CTkFrame(self.list_frame)
            row.pack(fill="x", padx=4, pady=4)
            ctk.CTkLabel(row, text=site, anchor="w").pack(side="left", fill="x", expand=True, padx=8)
            # lambda i=index: each Copy button remembers its own row index.
            ctk.CTkButton(
                row,
                text="Copy",
                width=70,
                command=lambda i=index: self.copy_password(i),
            ).pack(side="right", padx=4)

    def copy_password(self, index: int) -> None:
        if self.master_key is None or self.vault_name is None:
            return

        passwords_by_index = {idx: pw for idx, _site, pw in self.visible_entries}
        if index not in passwords_by_index:
            return
        pyperclip.copy(passwords_by_index[index])
        self.status_label.configure(text="Password copied to clipboard.")

    def add_entry_dialog(self) -> None:
        if self.master_key is None or self.vault_name is None:
            return

        dialog = ctk.CTkToplevel(self)
        dialog.title("Add entry")
        dialog.geometry("360x220")
        apply_window_icon(dialog)
        dialog.grab_set()  # keep focus on this popup until it closes

        site_entry = ctk.CTkEntry(dialog, placeholder_text="Site", width=280)
        site_entry.pack(pady=(32, 8))
        password_entry = ctk.CTkEntry(dialog, placeholder_text="Password", show="*", width=280)
        password_entry.pack(pady=(8, 16))

        def save() -> None:
            try:
                add_entry(
                    self.vault_name,
                    self.master_key,
                    site_entry.get().strip(),
                    password_entry.get(),
                )
                dialog.destroy()
                self.refresh_list()
                self.status_label.configure(text="Entry added.")
            except ValueError as exc:
                messagebox.showerror("Error", str(exc), parent=dialog)

        ctk.CTkButton(dialog, text="Save", command=save).pack(pady=12)


def run_gui() -> None:
    app = PasswordManagerApp()
    app.mainloop()


if __name__ == "__main__":
    run_gui()
