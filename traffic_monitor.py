from __future__ import annotations

import logging
import queue
import socket
import subprocess
import threading
import tkinter as tk
from dataclasses import dataclass, field
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Dict, Set

from scapy.all import IP, TCP, UDP, sniff


LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "network_monitor.log"
SIZE_THR = 10240
PORT_SCAN_THR = 5

LOG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


@dataclass
class SourceStats:
    total_bytes: int = 0
    unique_ports: Set[int] = field(default_factory=set)


@dataclass
class SuspiciousInfo:
    reason: str
    total_kb: float
    ports_count: int


class TrafficAnalyzer:
    """Business logic for traffic aggregation and suspicious detection."""

    def __init__(self, size_threshold_bytes: int = 10240, port_scan_threshold: int = 5) -> None:
        self.size_threshold_bytes = size_threshold_bytes
        self.port_scan_threshold = port_scan_threshold
        self.stats: Dict[str, SourceStats] = {}

    def reset(self) -> None:
        self.stats.clear()

    def feed_packet(self, source_ip: str, size_bytes: int, dst_port: int | None) -> SuspiciousInfo | None:
        if not source_ip:
            return None

        src = self.stats.setdefault(source_ip, SourceStats())
        src.total_bytes += max(size_bytes, 0)
        if dst_port is not None and dst_port >= 0:
            src.unique_ports.add(dst_port)

        return self.evaluate_source(source_ip)

    def evaluate_source(self, source_ip: str) -> SuspiciousInfo | None:
        src = self.stats.get(source_ip)
        if not src:
            return None

        if src.total_bytes >= self.size_threshold_bytes:
            return SuspiciousInfo(
                reason="Traffic Limit",
                total_kb=round(src.total_bytes / 1024, 2),
                ports_count=len(src.unique_ports),
            )

        if len(src.unique_ports) >= self.port_scan_threshold:
            return SuspiciousInfo(
                reason="Port Scanning",
                total_kb=round(src.total_bytes / 1024, 2),
                ports_count=len(src.unique_ports),
            )

        return None


class FirewallManager:
    """iptables wrapper for blocking and unblocking IP addresses."""

    def block_ip(self, ip_address: str) -> None:
        subprocess.run(["iptables", "-C", "INPUT", "-s", ip_address, "-j", "REJECT"], check=False)
        subprocess.run(["iptables", "-I", "INPUT", "-s", ip_address, "-j", "REJECT"], check=True)

    def unblock_ip(self, ip_address: str) -> None:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip_address, "-j", "REJECT"], check=True)


class TrafficMonitorApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Linux Traffic Monitor")
        self.root.geometry("1200x680")

        self.analyzer = TrafficAnalyzer(SIZE_THR, PORT_SCAN_THR)
        self.firewall = FirewallManager()

        self.stop_event = threading.Event()
        self.capture_thread: threading.Thread | None = None
        self.ui_events: queue.Queue[dict] = queue.Queue()
        self.blocked_ips: set[str] = set()

        self.self_ips = self._get_local_ipv4s()
        self.gateway_ip = self._get_default_gateway()

        self._build_ui()
        self._schedule_ui_pump()

    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self.root)
        toolbar.pack(fill=tk.X, padx=10, pady=8)

        self.start_btn = ttk.Button(toolbar, text="Start Monitor", command=self.start_monitoring)
        self.stop_btn = ttk.Button(toolbar, text="Stop Monitor", command=self.stop_monitoring, state=tk.DISABLED)
        self.block_btn = ttk.Button(toolbar, text="Block Selected IP", command=self.block_ip)
        self.unblock_btn = ttk.Button(toolbar, text="Unblock Selected IP", command=self.unblock_ip)

        self.start_btn.pack(side=tk.LEFT, padx=4)
        self.stop_btn.pack(side=tk.LEFT, padx=4)
        self.block_btn.pack(side=tk.LEFT, padx=4)
        self.unblock_btn.pack(side=tk.LEFT, padx=4)

        content = ttk.Frame(self.root)
        content.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        self.packet_table = self._mk_table(content, "Packet Log", ("src", "port", "size"), ("Source IP", "Port", "Size"), 0)
        self.suspicious_table = self._mk_table(
            content,
            "Suspicious",
            ("src", "reason", "total", "ports"),
            ("Source IP", "Reason", "Total (KB)", "Ports"),
            1,
        )
        self.blocked_table = self._mk_table(content, "Blocked", ("src",), ("Blocked IP",), 2)

        self.status_var = tk.StringVar(value="Status: idle")
        ttk.Label(self.root, textvariable=self.status_var).pack(fill=tk.X, padx=10, pady=(0, 8))

    def _mk_table(self, parent, title, columns, headings, col_idx):
        frame = ttk.LabelFrame(parent, text=title)
        frame.grid(row=0, column=col_idx, sticky="nsew", padx=6)
        parent.columnconfigure(col_idx, weight=1)
        parent.rowconfigure(0, weight=1)

        table = ttk.Treeview(frame, columns=columns, show="headings", height=24)
        for col, heading in zip(columns, headings):
            table.heading(col, text=heading)
            table.column(col, width=160, anchor=tk.CENTER)
        table.pack(fill=tk.BOTH, expand=True)
        return table

    def _schedule_ui_pump(self) -> None:
        self._process_ui_events()
        self.root.after(120, self._schedule_ui_pump)

    def _process_ui_events(self) -> None:
        while True:
            try:
                event = self.ui_events.get_nowait()
            except queue.Empty:
                return

            typ = event["type"]
            if typ == "packet":
                self.packet_table.insert("", tk.END, values=(event["src"], event["port"], event["size"]))
                if len(self.packet_table.get_children()) > 1200:
                    self.packet_table.delete(self.packet_table.get_children()[0])

            elif typ == "suspicious":
                self._upsert_suspicious(event["src"], event["reason"], event["total_kb"], event["ports"])

            elif typ == "status":
                self.status_var.set(event["text"])

    def start_monitoring(self) -> None:
        if self.capture_thread and self.capture_thread.is_alive():
            return

        self.analyzer.reset()
        self.stop_event.clear()
        self.packet_table.delete(*self.packet_table.get_children())
        self.suspicious_table.delete(*self.suspicious_table.get_children())

        self.capture_thread = threading.Thread(target=self.monitor_traffic, daemon=True)
        self.capture_thread.start()

        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.ui_events.put({"type": "status", "text": "Status: monitoring"})
        logging.info("Monitoring started")

    def stop_monitoring(self) -> None:
        self.stop_event.set()
        self.start_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        self.ui_events.put({"type": "status", "text": "Status: stopped"})
        logging.info("Monitoring stopped")

    def monitor_traffic(self) -> None:
        def stop_filter(_packet):
            return self.stop_event.is_set()

        sniff(prn=self.packet_callback, store=False, stop_filter=stop_filter)

    def packet_callback(self, packet) -> None:
        if IP not in packet:
            return

        source_ip = packet[IP].src
        dst_port = None
        if TCP in packet:
            dst_port = int(packet[TCP].dport)
        elif UDP in packet:
            dst_port = int(packet[UDP].dport)

        size = len(packet)
        self.ui_events.put({"type": "packet", "src": source_ip, "port": dst_port if dst_port is not None else "-", "size": size})

        suspicious = self.analyzer.feed_packet(source_ip, size, dst_port)
        if suspicious:
            self.ui_events.put(
                {
                    "type": "suspicious",
                    "src": source_ip,
                    "reason": suspicious.reason,
                    "total_kb": suspicious.total_kb,
                    "ports": suspicious.ports_count,
                }
            )
            logging.warning("Suspicious IP %s (%s, %.2f KB, ports=%s)", source_ip, suspicious.reason, suspicious.total_kb, suspicious.ports_count)

    def block_ip(self) -> None:
        selected = self.suspicious_table.selection()
        if not selected:
            messagebox.showwarning("Warning", "Select an IP from Suspicious table")
            return

        values = self.suspicious_table.item(selected[0], "values")
        ip_address = values[0]
        if not self._can_block(ip_address):
            messagebox.showerror("Safety", f"Cannot block protected IP: {ip_address}")
            return

        try:
            self.firewall.block_ip(ip_address)
        except Exception as exc:
            logging.exception("Failed to block %s: %s", ip_address, exc)
            messagebox.showerror("Error", f"Failed to block {ip_address}\n{exc}")
            return

        self.blocked_ips.add(ip_address)
        self._upsert_blocked(ip_address)
        logging.info("Blocked IP %s", ip_address)

    def unblock_ip(self) -> None:
        selected = self.blocked_table.selection()
        if not selected:
            messagebox.showwarning("Warning", "Select an IP from Blocked table")
            return

        ip_address = self.blocked_table.item(selected[0], "values")[0]
        try:
            self.firewall.unblock_ip(ip_address)
        except Exception as exc:
            logging.exception("Failed to unblock %s: %s", ip_address, exc)
            messagebox.showerror("Error", f"Failed to unblock {ip_address}\n{exc}")
            return

        self.blocked_ips.discard(ip_address)
        self.blocked_table.delete(selected[0])
        logging.info("Unblocked IP %s", ip_address)

    def _upsert_suspicious(self, source_ip: str, reason: str, total_kb: float, ports: int) -> None:
        for item in self.suspicious_table.get_children():
            row = self.suspicious_table.item(item, "values")
            if row[0] == source_ip:
                self.suspicious_table.item(item, values=(source_ip, reason, total_kb, ports))
                return
        self.suspicious_table.insert("", tk.END, values=(source_ip, reason, total_kb, ports))

    def _upsert_blocked(self, source_ip: str) -> None:
        for item in self.blocked_table.get_children():
            row = self.blocked_table.item(item, "values")
            if row[0] == source_ip:
                return
        self.blocked_table.insert("", tk.END, values=(source_ip,))

    def _can_block(self, ip_address: str) -> bool:
        if ip_address in self.self_ips:
            return False
        if self.gateway_ip and ip_address == self.gateway_ip:
            return False
        return True

    def _get_local_ipv4s(self) -> set[str]:
        result = {"127.0.0.1"}
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None, family=socket.AF_INET):
            result.add(info[4][0])
        return result

    def _get_default_gateway(self) -> str | None:
        try:
            proc = subprocess.run(["ip", "route", "show", "default"], check=False, capture_output=True, text=True)
            if proc.returncode != 0:
                return None
            parts = proc.stdout.split()
            if "via" in parts:
                idx = parts.index("via")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
            return None
        except Exception:
            return None


def main() -> None:
    root = tk.Tk()
    app = TrafficMonitorApp(root)
    root.protocol("WM_DELETE_WINDOW", app.stop_monitoring)
    root.mainloop()


if __name__ == "__main__":
    main()
