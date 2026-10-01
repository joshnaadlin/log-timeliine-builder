import csv
import json
import sys
import threading
import queue
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_TITLE = "FORENSIGHT | Digital Forensics Log Timeline Builder"

BG = "#0b1020"
PANEL = "#111a2e"
PANEL2 = "#17233b"
BORDER = "#263653"
TEXT = "#e8eefc"
MUTED = "#8fa2c7"
ACCENT = "#54d6ff"
GREEN = "#57e39b"
ORANGE = "#ffbd69"
RED = "#ff6b81"
PURPLE = "#b7a0ff"


# ============================================================
# DATA MODEL
# ============================================================

@dataclass
class LogEvent:
    timestamp: str
    event_type: str
    source: str
    description: str
    host: str = ""
    user: str = ""
    source_ip: str = ""
    severity: str = "Info"
    event_id: str = ""
    event_id_internal: int = 0


# ============================================================
# SINGLY LINKED LIST
# ============================================================

class Node:
    def __init__(self, event):
        self.event = event
        self.next = None


class EventLinkedList:
    def __init__(self):
        self.head = None
        self.tail = None
        self.size = 0

    def append(self, event):
        node = Node(event)

        if self.head is None:
            self.head = node
            self.tail = node
        else:
            self.tail.next = node
            self.tail = node

        self.size += 1

    def traverse(self):
        current = self.head

        while current:
            yield current.event
            current = current.next

    def clear(self):
        self.head = None
        self.tail = None
        self.size = 0

    def delete_by_internal_id(self, internal_id):
        current = self.head
        previous = None

        while current:

            if current.event.event_id_internal == internal_id:

                if previous is None:
                    self.head = current.next
                else:
                    previous.next = current.next

                if current == self.tail:
                    self.tail = previous

                self.size -= 1
                return True

            previous = current
            current = current.next

        return False

    def find(self, keyword):
        keyword = keyword.casefold().strip()

        if not keyword:
            return list(self.traverse())

        results = []

        for event in self.traverse():
            values = " ".join(
                str(value) for value in asdict(event).values()
            )

            if keyword in values.casefold():
                results.append(event)

        return results

    def replace_all(self, events):
        self.clear()

        for event in events:
            self.append(event)


# ============================================================
# DATE AND LOG PROCESSING
# ============================================================

def parse_datetime(value):
    if not value:
        return None

    value = str(value).strip()

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%m/%d/%Y %I:%M:%S %p",
        "%d-%m-%Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%fZ",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(value.replace("Z", ""), fmt)
        except ValueError:
            pass

    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        ).replace(tzinfo=None)
    except ValueError:
        return None


def normalize_timestamp(value):
    dt = parse_datetime(value)

    if dt:
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    return str(value or datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    ))


def event_from_mapping(row, source_name="Imported"):

    lower = {
        str(k).strip().lower().replace(" ", "_"): v
        for k, v in row.items()
        if k is not None
    }

    def pick(*names, default=""):
        for name in names:
            if name in lower and lower[name] not in (None, ""):
                return str(lower[name]).strip()

        return default

    timestamp = pick(
        "timestamp", "time_created", "time",
        "date", "datetime", "created"
    )

    return LogEvent(
        timestamp=normalize_timestamp(timestamp),
        event_type=pick(
            "event_type", "type", "category",
            default="System Event"
        ),
        source=pick(
            "source", "provider", "log_name",
            default=source_name
        ),
        description=pick(
            "description", "message", "details",
            "event", default="Imported log entry"
        ),
        host=pick(
            "host", "computer", "computer_name", "hostname"
        ),
        user=pick("user", "username", "account"),
        source_ip=pick(
            "source_ip", "ip", "ip_address",
            "client_ip", "source_network_address"
        ),
        severity=pick(
            "severity", "level", "event_level",
            default="Info"
        ),
        event_id=pick("event_id", "eventid", "id")
    )


def parse_csv(path):
    events = []

    with open(
        path, "r", encoding="utf-8-sig",
        newline="", errors="replace"
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:
            events.append(
                event_from_mapping(row, Path(path).name)
            )

    return events


def parse_json(path):
    with open(path, "r", encoding="utf-8-sig") as file:
        data = json.load(file)

    if isinstance(data, dict):
        data = data.get(
            "events",
            data.get("logs", [data])
        )

    if not isinstance(data, list):
        raise ValueError("JSON must contain a list of events.")

    return [
        event_from_mapping(item, Path(path).name)
        for item in data
        if isinstance(item, dict)
    ]


def parse_evtx(path):

    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        raise RuntimeError(
            "Install EVTX support using:\n"
            "pip install python-evtx"
        )

    events = []

    with Evtx(path) as log:

        for record in log.records():

            try:
                root = ET.fromstring(record.xml())

                ns = {
                    "e": (
                        "http://schemas.microsoft.com/"
                        "win/2004/08/events/event"
                    )
                }

                system = root.find("e:System", ns)

                if system is None:
                    continue

                provider = system.find("e:Provider", ns)
                eventid = system.find("e:EventID", ns)
                level = system.find("e:Level", ns)
                time_node = system.find("e:TimeCreated", ns)
                computer = system.find("e:Computer", ns)

                timestamp = ""

                if time_node is not None:
                    timestamp = time_node.attrib.get(
                        "SystemTime", ""
                    )

                data = []

                for item in root.findall(
                    ".//e:EventData/e:Data", ns
                ):
                    name = item.attrib.get("Name", "")
                    value = item.text or ""

                    if name:
                        data.append(f"{name}={value}")
                    elif value:
                        data.append(value)

                description = "; ".join(data)

                if not description:
                    description = (
                        "Windows event record"
                    )

                severity = "Info"

                if level is not None and level.text:
                    levels = {
                        "1": "Critical",
                        "2": "Error",
                        "3": "Warning",
                        "4": "Info",
                        "5": "Verbose"
                    }

                    severity = levels.get(
                        level.text, "Info"
                    )

                events.append(
                    LogEvent(
                        timestamp=normalize_timestamp(
                            timestamp
                        ),
                        event_type="Windows Event",
                        source=(
                            provider.attrib.get("Name", "")
                            if provider is not None
                            else "Windows Event Log"
                        ),
                        description=description,
                        host=(
                            computer.text
                            if computer is not None
                            else ""
                        ),
                        severity=severity,
                        event_id=(
                            eventid.text
                            if eventid is not None
                            else ""
                        )
                    )
                )

            except Exception:
                continue

    return events


def parse_file(path):
    ext = Path(path).suffix.lower()

    if ext in (".csv", ".tsv", ".txt"):
        return parse_csv(path)

    if ext == ".json":
        return parse_json(path)

    if ext == ".evtx":
        return parse_evtx(path)

    raise ValueError("Unsupported file format.")


# ============================================================
# MAIN TKINTER APPLICATION
# ============================================================

class TimelineApp:

    def __init__(self, root):

        self.root = root

        self.root.title(APP_TITLE)
        self.root.geometry("1420x850")
        self.root.minsize(1100, 700)
        self.root.configure(bg=BG)

        self.events = EventLinkedList()
        self.next_id = 1
        self.queue = queue.Queue()

        self.sort_key = tk.StringVar(
            value="timestamp"
        )

        self.sort_order = tk.StringVar(
            value="Oldest first"
        )

        self.search_var = tk.StringVar()
        self.filter_var = tk.StringVar(
            value="All severities"
        )

        self.status_var = tk.StringVar(
            value="Linked-list engine initialized"
        )

        self.configure_style()
        self.build_ui()
        self.load_demo()

        self.root.after(
            120, self.process_queue
        )

    # --------------------------------------------------------
    # STYLE
    # --------------------------------------------------------

    def configure_style(self):

        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "Treeview",
            background=PANEL,
            foreground=TEXT,
            fieldbackground=PANEL,
            rowheight=30,
            borderwidth=0,
            font=("Segoe UI", 9)
        )

        style.configure(
            "Treeview.Heading",
            background=PANEL2,
            foreground=ACCENT,
            font=("Segoe UI", 9, "bold")
        )

        style.map(
            "Treeview",
            background=[("selected", "#21486b")],
            foreground=[("selected", "#ffffff")]
        )

        style.configure(
            "TCombobox",
            fieldbackground=PANEL2,
            background=PANEL2,
            foreground=TEXT,
            arrowcolor=ACCENT
        )

    def button(self, parent, text, command,
               color=PANEL2, fg=TEXT):

        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=color,
            fg=fg,
            activebackground=ACCENT,
            activeforeground=BG,
            relief="flat",
            bd=0,
            padx=12,
            pady=9,
            cursor="hand2",
            font=("Segoe UI", 9, "bold")
        )

    # --------------------------------------------------------
    # USER INTERFACE
    # --------------------------------------------------------

    def build_ui(self):

        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", padx=24, pady=18)

        title = tk.Label(
            header,
            text="FORENSIGHT",
            bg=BG,
            fg=ACCENT,
            font=("Segoe UI", 22, "bold")
        )

        title.pack(side="left")

        self.button(
            header,
            "＋ Add Event",
            self.add_dialog,
            ACCENT,
            BG
        ).pack(side="right", padx=5)

        self.button(
            header,
            "⇧ Import Logs",
            self.import_logs
        ).pack(side="right", padx=5)

        self.button(
            header,
            "Collect Windows Logs",
            self.collect_windows_logs
        ).pack(side="right", padx=5)

        stats = tk.Frame(self.root, bg=BG)
        stats.pack(fill="x", padx=24, pady=(0, 14))

        self.total_label = self.stat_card(
            stats, "TOTAL EVENTS", ACCENT
        )

        self.alert_label = self.stat_card(
            stats, "HIGH / ERROR", RED
        )

        self.source_label = self.stat_card(
            stats, "SOURCES", PURPLE
        )

        self.range_label = self.stat_card(
            stats, "TIME SPAN", GREEN
        )

        main = tk.Frame(self.root, bg=BG)
        main.pack(
            fill="both",
            expand=True,
            padx=24,
            pady=(0, 12)
        )

        left = tk.Frame(
            main,
            bg=PANEL,
            highlightbackground=BORDER,
            highlightthickness=1
        )

        left.pack(
            side="left",
            fill="both",
            expand=True
        )

        right = tk.Frame(
            main,
            bg=PANEL,
            width=300,
            highlightbackground=BORDER,
            highlightthickness=1
        )

        right.pack(
            side="right",
            fill="y",
            padx=(14, 0)
        )

        right.pack_propagate(False)

        # Search toolbar

        toolbar = tk.Frame(left, bg=PANEL)
        toolbar.pack(fill="x", padx=14, pady=14)

        search = tk.Entry(
            toolbar,
            textvariable=self.search_var,
            bg=PANEL2,
            fg=TEXT,
            insertbackground=ACCENT,
            relief="flat"
        )

        search.pack(
            side="left",
            fill="x",
            expand=True,
            ipady=9,
            padx=(0, 10)
        )

        search.bind(
            "<KeyRelease>",
            lambda event: self.refresh_table()
        )

        filter_box = ttk.Combobox(
            toolbar,
            textvariable=self.filter_var,
            state="readonly",
            values=[
                "All severities",
                "Critical / Error",
                "Warning",
                "Info / Other"
            ],
            width=16
        )

        filter_box.pack(side="right")

        filter_box.bind(
            "<<ComboboxSelected>>",
            lambda event: self.refresh_table()
        )

        # Sorting toolbar

        sortbar = tk.Frame(left, bg=PANEL)
        sortbar.pack(fill="x", padx=14, pady=(0, 10))

        tk.Label(
            sortbar,
            text="SORT BY",
            bg=PANEL,
            fg=ACCENT
        ).pack(side="left", padx=5)

        sortbox = ttk.Combobox(
            sortbar,
            textvariable=self.sort_key,
            state="readonly",
            values=[
                "timestamp",
                "severity",
                "event_type",
                "source",
                "host",
                "user"
            ],
            width=14
        )

        sortbox.pack(side="left")

        sortbox.bind(
            "<<ComboboxSelected>>",
            lambda event: self.refresh_table()
        )

        orderbox = ttk.Combobox(
            sortbar,
            textvariable=self.sort_order,
            state="readonly",
            values=[
                "Oldest first",
                "Newest first"
            ],
            width=14
        )

        orderbox.pack(side="left", padx=6)

        orderbox.bind(
            "<<ComboboxSelected>>",
            lambda event: self.refresh_table()
        )

        self.button(
            sortbar,
            "Reset",
            self.reset_filters
        ).pack(side="left", padx=5)

        self.button(
            sortbar,
            "Delete Selected",
            self.delete_selected,
            "#3b2033",
            "#ffb4c0"
        ).pack(side="right")

        # Timeline table

        columns = (
            "timestamp",
            "severity",
            "event_type",
            "source",
            "event_id",
            "host",
            "description"
        )

        self.tree = ttk.Treeview(
            left,
            columns=columns,
            show="headings",
            selectmode="extended"
        )

        headings = {
            "timestamp": "TIMESTAMP",
            "severity": "SEVERITY",
            "event_type": "EVENT TYPE",
            "source": "SOURCE",
            "event_id": "EVENT ID",
            "host": "HOST",
            "description": "DESCRIPTION"
        }

        widths = {
            "timestamp": 155,
            "severity": 90,
            "event_type": 125,
            "source": 150,
            "event_id": 75,
            "host": 130,
            "description": 350
        }

        for col in columns:
            self.tree.heading(
                col, text=headings[col]
            )

            self.tree.column(
                col,
                width=widths[col],
                minwidth=70,
                anchor="w"
            )

        self.tree.pack(
            fill="both",
            expand=True,
            padx=14,
            pady=8
        )

        self.tree.bind(
            "<<TreeviewSelect>>",
            self.show_details
        )

        # Event inspector

        tk.Label(
            right,
            text="EVENT INSPECTOR",
            bg=PANEL,
            fg=ACCENT,
            font=("Segoe UI", 11, "bold")
        ).pack(anchor="w", padx=16, pady=15)

        self.details = tk.Text(
            right,
            bg=PANEL2,
            fg=TEXT,
            relief="flat",
            wrap="word",
            font=("Consolas", 9)
        )

        self.details.pack(
            fill="both",
            expand=True,
            padx=14,
            pady=8
        )

        self.details.insert(
            "1.0",
            "Select an event to inspect its details."
        )

        self.details.configure(state="disabled")

        self.button(
            right,
            "Export Timeline CSV",
            self.export_csv
        ).pack(fill="x", padx=14, pady=4)

        self.button(
            right,
            "Save Case JSON",
            self.save_case
        ).pack(fill="x", padx=14, pady=4)

        self.button(
            right,
            "Open Case JSON",
            self.open_case
        ).pack(fill="x", padx=14, pady=4)

        self.button(
            right,
            "Delete All Events",
            self.clear_all,
            "#3b2033",
            "#ffb4c0"
        ).pack(fill="x", padx=14, pady=10)

        footer = tk.Frame(
            self.root,
            bg="#070b16"
        )

        footer.pack(fill="x", side="bottom")

        tk.Label(
            footer,
            text="● LINKED LIST ACTIVE",
            bg="#070b16",
            fg=GREEN
        ).pack(side="left", padx=24, pady=9)

        tk.Label(
            footer,
            textvariable=self.status_var,
            bg="#070b16",
            fg=MUTED
        ).pack(side="right", padx=24, pady=9)

    def stat_card(self, parent, title, color):

        card = tk.Frame(
            parent,
            bg=PANEL,
            highlightbackground=BORDER,
            highlightthickness=1
        )

        card.pack(
            side="left",
            fill="x",
            expand=True,
            padx=(0, 10)
        )

        tk.Label(
            card,
            text=title,
            bg=PANEL,
            fg=MUTED
        ).pack(anchor="w", padx=14, pady=(10, 2))

        value = tk.Label(
            card,
            text="0",
            bg=PANEL,
            fg=color,
            font=("Segoe UI", 18, "bold")
        )

        value.pack(anchor="w", padx=14, pady=(0, 10))

        return value

    # --------------------------------------------------------
    # DEMO EVENTS
    # --------------------------------------------------------

    def load_demo(self):

        demo = [
            LogEvent(
                "2026-09-27 09:14:02",
                "Authentication",
                "Windows Security",
                "Several failed sign-in attempts detected",
                "LAB-PC", "unknown", "192.0.2.44",
                "Warning", "4625"
            ),
            LogEvent(
                "2026-09-27 09:16:31",
                "Authentication",
                "Windows Security",
                "Successful account logon after repeated failures",
                "LAB-PC", "analyst-demo", "192.0.2.44",
                "High", "4624"
            ),
            LogEvent(
                "2026-09-27 09:19:10",
                "Process Activity",
                "Sysmon",
                "Unusual process launched from user-writable directory",
                "LAB-PC", "analyst-demo", "",
                "High", "1"
            ),
            LogEvent(
                "2026-09-27 09:23:48",
                "File Activity",
                "File System",
                "New executable created in temporary folder",
                "LAB-PC", "analyst-demo", "",
                "Warning", "11"
            ),
            LogEvent(
                "2026-09-27 09:29:05",
                "Network",
                "Sysmon",
                "Outbound connection to an unrecognized address",
                "LAB-PC", "analyst-demo", "198.51.100.23",
                "Critical", "3"
            )
        ]

        for event in demo:
            self.insert_event(event, False)

        self.refresh_table()

        self.status_var.set(
            "Synthetic training events loaded"
        )

    # --------------------------------------------------------
    # INSERT EVENT
    # --------------------------------------------------------

    def insert_event(self, event, refresh=True):

        event.event_id_internal = self.next_id
        self.next_id += 1

        self.events.append(event)

        if refresh:
            self.refresh_table()

    # --------------------------------------------------------
    # SEARCH, FILTER AND SORT
    # --------------------------------------------------------

    def refresh_table(self):

        for item in self.tree.get_children():
            self.tree.delete(item)

        keyword = self.search_var.get()

        matches = self.events.find(keyword)

        selected_filter = self.filter_var.get()

        if selected_filter == "Critical / Error":

            matches = [
                e for e in matches
                if any(
                    x in e.severity.lower()
                    for x in (
                        "critical", "error",
                        "high", "fatal"
                    )
                )
            ]

        elif selected_filter == "Warning":

            matches = [
                e for e in matches
                if "warn" in e.severity.lower()
                or "medium" in e.severity.lower()
                or "suspicious" in e.severity.lower()
            ]

        elif selected_filter == "Info / Other":

            matches = [
                e for e in matches
                if not any(
                    x in e.severity.lower()
                    for x in (
                        "critical", "error",
                        "high", "fatal",
                        "warn", "medium",
                        "suspicious"
                    )
                )
            ]

        key = self.sort_key.get()

        reverse = (
            self.sort_order.get() == "Newest first"
        )

        if key == "timestamp":

            matches.sort(
                key=lambda e: (
                    parse_datetime(e.timestamp)
                    or datetime.min
                ),
                reverse=reverse
            )

        else:

            matches.sort(
                key=lambda e: str(
                    getattr(e, key, "")
                ).casefold(),
                reverse=reverse
            )

        for event in matches:

            self.tree.insert(
                "",
                "end",
                iid=str(event.event_id_internal),
                values=(
                    event.timestamp,
                    event.severity,
                    event.event_type,
                    event.source,
                    event.event_id,
                    event.host,
                    event.description
                )
            )

        self.update_stats()

    def reset_filters(self):

        self.search_var.set("")
        self.filter_var.set("All severities")
        self.sort_key.set("timestamp")
        self.sort_order.set("Oldest first")

        self.refresh_table()

    # --------------------------------------------------------
    # STATISTICS
    # --------------------------------------------------------

    def update_stats(self):

        events = list(self.events.traverse())

        self.total_label.config(
            text=str(len(events))
        )

        alerts = sum(
            1 for e in events
            if any(
                x in e.severity.lower()
                for x in (
                    "critical", "error",
                    "high", "fatal"
                )
            )
        )

        self.alert_label.config(text=str(alerts))

        sources = len(
            set(e.source for e in events if e.source)
        )

        self.source_label.config(text=str(sources))

        times = [
            parse_datetime(e.timestamp)
            for e in events
        ]

        times = [t for t in times if t]

        if times:

            self.range_label.config(
                text=(
                    f"{min(times).strftime('%b %d')} - "
                    f"{max(times).strftime('%b %d')}"
                )
            )

        else:
            self.range_label.config(text="—")

    # --------------------------------------------------------
    # ADD MANUAL EVENT
    # --------------------------------------------------------

    def add_dialog(self):

        win = tk.Toplevel(self.root)
        win.title("Add Forensic Event")
        win.geometry("550x650")
        win.configure(bg=PANEL)
        win.transient(self.root)
        win.grab_set()

        tk.Label(
            win,
            text="ADD FORENSIC EVENT",
            bg=PANEL,
            fg=ACCENT,
            font=("Segoe UI", 15, "bold")
        ).pack(anchor="w", padx=22, pady=18)

        form = tk.Frame(win, bg=PANEL)
        form.pack(fill="both", expand=True, padx=22)

        fields = {}

        definitions = [
            ("Timestamp", "timestamp",
             datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            ("Event Type", "event_type", "System Event"),
            ("Source", "source", "Manual Entry"),
            ("Severity", "severity", "Info"),
            ("Event ID", "event_id", ""),
            ("Host", "host", ""),
            ("User", "user", ""),
            ("Source IP", "source_ip", "")
        ]

        for label, key, default in definitions:

            tk.Label(
                form,
                text=label,
                bg=PANEL,
                fg=MUTED
            ).pack(anchor="w", pady=(4, 2))

            entry = tk.Entry(
                form,
                bg=PANEL2,
                fg=TEXT,
                insertbackground=ACCENT,
                relief="flat"
            )

            entry.pack(fill="x", ipady=6)
            entry.insert(0, default)

            fields[key] = entry

        tk.Label(
            form,
            text="Description",
            bg=PANEL,
            fg=MUTED
        ).pack(anchor="w", pady=(8, 2))

        description = tk.Text(
            form,
            height=4,
            bg=PANEL2,
            fg=TEXT,
            relief="flat"
        )

        description.pack(fill="x")

        def save():

            timestamp = fields["timestamp"].get()

            if not parse_datetime(timestamp):
                messagebox.showerror(
                    "Invalid timestamp",
                    "Enter a valid date and time.",
                    parent=win
                )
                return

            event = LogEvent(
                timestamp=normalize_timestamp(timestamp),
                event_type=fields["event_type"].get(),
                source=fields["source"].get(),
                description=description.get(
                    "1.0", "end"
                ).strip(),
                severity=fields["severity"].get(),
                event_id=fields["event_id"].get(),
                host=fields["host"].get(),
                user=fields["user"].get(),
                source_ip=fields["source_ip"].get()
            )

            self.insert_event(event)

            self.status_var.set(
                "Event inserted into linked list"
            )

            win.destroy()

        self.button(
            win,
            "Save Event",
            save,
            ACCENT,
            BG
        ).pack(fill="x", padx=22, pady=18)

    # --------------------------------------------------------
    # IMPORT LOG FILES
    # --------------------------------------------------------

    def import_logs(self):

        paths = filedialog.askopenfilenames(
            title="Import Forensic Logs",
            filetypes=[
                ("Supported Logs",
                 "*.csv *.json *.evtx *.tsv *.txt"),
                ("All Files", "*.*")
            ]
        )

        if not paths:
            return

        self.status_var.set("Importing log files...")

        def worker():

            imported = []
            errors = []

            for path in paths:

                try:
                    imported.extend(
                        parse_file(path)
                    )

                except Exception as exc:
                    errors.append(
                        f"{Path(path).name}: {exc}"
                    )

            self.queue.put(
                ("import", imported, errors)
            )

        threading.Thread(
            target=worker,
            daemon=True
        ).start()

    # --------------------------------------------------------
    # DIRECT WINDOWS LOG COLLECTION
    # --------------------------------------------------------

    def collect_windows_logs(self):

        if sys.platform != "win32":

            messagebox.showinfo(
                "Windows Only",
                "This feature works only on Windows."
            )

            return

        if not messagebox.askyesno(
            "Collect Windows Logs",
            "Read recent local Windows System, Security "
            "and Application logs?\n\n"
            "Security log access may require administrator "
            "permission."
        ):
            return

        self.status_var.set(
            "Collecting Windows logs..."
        )

        def worker():

            try:
                import win32evtlog

                collected = []

                for log_type in (
                    "System",
                    "Security",
                    "Application"
                ):

                    try:

                        handle = win32evtlog.OpenEventLog(
                            "localhost",
                            log_type
                        )

                        flags = (
                            win32evtlog.EVENTLOG_BACKWARDS_READ
                            | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                        )

                        records = (
                            win32evtlog.ReadEventLog(
                                handle, flags, 0
                            ) or []
                        )

                        for rec in records[:300]:

                            strings = " | ".join(
                                str(s)
                                for s in (
                                    rec.StringInserts or []
                                )
                            )

                            severity = {
                                1: "Error",
                                2: "Warning",
                                4: "Info"
                            }.get(rec.EventType, "Info")

                            collected.append(
                                LogEvent(
                                    timestamp=normalize_timestamp(
                                        rec.TimeGenerated.Format()
                                    ),
                                    event_type=log_type,
                                    source=str(
                                        rec.SourceName or log_type
                                    ),
                                    description=(
                                        strings
                                        or f"Windows event {rec.EventID}"
                                    ),
                                    host=str(
                                        rec.ComputerName or ""
                                    ),
                                    severity=severity,
                                    event_id=str(
                                        rec.EventID & 0xFFFF
                                    )
                                )
                            )

                        win32evtlog.CloseEventLog(handle)

                    except Exception as exc:

                        self.queue.put(
                            (
                                "notice",
                                f"Could not read {log_type}: {exc}"
                            )
                        )

                self.queue.put(
                    ("import", collected, [])
                )

            except ImportError:

                self.queue.put(
                    (
                        "notice",
                        "Install pywin32:\n"
                        "py -m pip install pywin32"
                    )
                )

        threading.Thread(
            target=worker,
            daemon=True
        ).start()

    def process_queue(self):

        try:

            while True:

                item = self.queue.get_nowait()

                if item[0] == "import":

                    _, imported, errors = item

                    for event in imported:
                        self.insert_event(
                            event, refresh=False
                        )

                    self.refresh_table()

                    self.status_var.set(
                        f"Imported {len(imported)} events"
                    )

                    message = (
                        f"Imported {len(imported)} events."
                    )

                    if errors:
                        message += "\n\n" + "\n".join(
                            errors[:8]
                        )

                    messagebox.showinfo(
                        "Import Complete",
                        message
                    )

                elif item[0] == "notice":

                    messagebox.showwarning(
                        "Notice", item[1]
                    )

        except queue.Empty:
            pass

        self.root.after(
            120, self.process_queue
        )

    # --------------------------------------------------------
    # EVENT DETAILS
    # --------------------------------------------------------

    def selected_event(self):

        selection = self.tree.selection()

        if not selection:
            return None

        internal_id = int(selection[0])

        for event in self.events.traverse():

            if event.event_id_internal == internal_id:
                return event

        return None

    def show_details(self, event=None):

        selected = self.selected_event()

        if not selected:
            return

        details = (
            f"TIMESTAMP\n{selected.timestamp}\n\n"
            f"SEVERITY\n{selected.severity}\n\n"
            f"EVENT TYPE\n{selected.event_type}\n\n"
            f"SOURCE\n{selected.source}\n\n"
            f"EVENT ID\n{selected.event_id}\n\n"
            f"HOST\n{selected.host}\n\n"
            f"USER\n{selected.user}\n\n"
            f"SOURCE IP\n{selected.source_ip}\n\n"
            f"DESCRIPTION\n{selected.description}\n\n"
            f"LINKED LIST NODE\n"
            f"{selected.event_id_internal}"
        )

        self.details.configure(state="normal")

        self.details.delete("1.0", "end")
        self.details.insert("1.0", details)

        self.details.configure(state="disabled")

    # --------------------------------------------------------
    # DELETE EVENTS
    # --------------------------------------------------------

    def delete_selected(self):

        selection = self.tree.selection()

        if not selection:
            messagebox.showinfo(
                "Select Event",
                "Select one or more events first."
            )
            return

        if not messagebox.askyesno(
            "Delete Selected",
            f"Delete {len(selection)} selected events?"
        ):
            return

        for iid in selection:
            self.events.delete_by_internal_id(
                int(iid)
            )

        self.refresh_table()

        self.status_var.set(
            "Selected events deleted"
        )

    def clear_all(self):

        if not self.events.size:
            return

        if messagebox.askyesno(
            "Delete All",
            f"Delete all {self.events.size} events?"
        ):

            self.events.clear()
            self.refresh_table()

            self.details.configure(state="normal")
            self.details.delete("1.0", "end")
            self.details.insert(
                "1.0",
                "Timeline cleared."
            )
            self.details.configure(state="disabled")

            self.status_var.set(
                "Linked list cleared"
            )

    # --------------------------------------------------------
    # EXPORT CSV
    # --------------------------------------------------------

    def export_csv(self):

        if not self.events.size:
            messagebox.showinfo(
                "No Events",
                "There are no events to export."
            )
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV File", "*.csv")],
            initialfile="forensic_timeline.csv"
        )

        if not path:
            return

        fields = [
            "timestamp", "event_type", "source",
            "description", "host", "user",
            "source_ip", "severity", "event_id",
            "event_id_internal"
        ]

        with open(
            path,
            "w",
            newline="",
            encoding="utf-8-sig"
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=fields
            )

            writer.writeheader()

            events = sorted(
                self.events.traverse(),
                key=lambda e: (
                    parse_datetime(e.timestamp)
                    or datetime.min
                )
            )

            for event in events:
                writer.writerow(asdict(event))

        messagebox.showinfo(
            "Export Complete",
            f"Timeline exported to:\n{path}"
        )

    # --------------------------------------------------------
    # SAVE CASE JSON
    # --------------------------------------------------------

    def save_case(self):

        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Case", "*.json")],
            initialfile="forensic_case.json"
        )

        if not path:
            return

        payload = {
            "case_name": Path(path).stem,
            "created_at": datetime.now().isoformat(),
            "events": [
                asdict(e)
                for e in self.events.traverse()
            ]
        }

        with open(
            path, "w", encoding="utf-8"
        ) as file:

            json.dump(
                payload,
                file,
                indent=4,
                ensure_ascii=False
            )

        messagebox.showinfo(
            "Case Saved",
            f"Saved {self.events.size} events."
        )

    # --------------------------------------------------------
    # OPEN CASE JSON
    # --------------------------------------------------------

    def open_case(self):

        path = filedialog.askopenfilename(
            filetypes=[("JSON Case", "*.json")]
        )

        if not path:
            return

        try:

            with open(
                path, "r", encoding="utf-8"
            ) as file:

                payload = json.load(file)

            raw = (
                payload.get("events", [])
                if isinstance(payload, dict)
                else payload
            )

            if not isinstance(raw, list):
                raise ValueError(
                    "Invalid case JSON format."
                )

            if not messagebox.askyesno(
                "Open Case",
                "Replace the current timeline?"
            ):
                return

            self.events.clear()

            for item in raw:

                if isinstance(item, dict):

                    event = LogEvent(
                        timestamp=item.get("timestamp", ""),
                        event_type=item.get("event_type", ""),
                        source=item.get("source", ""),
                        description=item.get("description", ""),
                        host=item.get("host", ""),
                        user=item.get("user", ""),
                        source_ip=item.get("source_ip", ""),
                        severity=item.get("severity", "Info"),
                        event_id=item.get("event_id", "")
                    )

                    self.insert_event(
                        event, refresh=False
                    )

            self.refresh_table()

            self.status_var.set(
                f"Opened case: {Path(path).name}"
            )

        except Exception as exc:

            messagebox.showerror(
                "Could Not Open Case",
                str(exc)
            )


# ============================================================
# RUN APPLICATION
# ============================================================

def main():

    root = tk.Tk()

    app = TimelineApp(root)

    root.mainloop()


if __name__ == "__main__":
    main()