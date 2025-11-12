#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
System Health Reporter
======================
Cross-platform system monitoring and reporting tool for Windows, macOS, and Linux.
Generates comprehensive health reports in multiple formats (CSV, JSON, YAML, HTML).

Author: memarzade-dev
License: MIT
Python: 3.8+

Features:
- Collects hardware, OS, CPU, memory, disk, GPU, network, processes
- Driver enumeration and installed software inventory
- Battery/power status and temperature sensors
- Multiple output formats with rich HTML dashboard
- No admin required (degrades gracefully)
- Dependencies: psutil (pinned), wmi (Windows-only, pinned)
"""

from __future__ import annotations
import csv
import json
import logging
import os
import platform
import shutil
import socket
import subprocess
import sys
from datetime import datetime
from html import escape  # Added for HTML sanitization
from typing import Dict, Any, List, Tuple, Optional

# =============================================================================
# CONSTANTS
# =============================================================================

VERSION = "1.0.1"  # Bumped for production release
DEFAULT_OUTPUT_DIR = os.path.join(os.path.expanduser("~"), "system_health_reports")
REQUIRED_PACKAGES = ["psutil==6.1.0"]  # Pinned for reproducibility
if platform.system() == "Windows":
    REQUIRED_PACKAGES.append("wmi==1.5.1")  # Pinned

# Setup logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# =============================================================================
# DEPENDENCY INSTALLER
# =============================================================================

def ensure_dependencies(packages: List[str], auto_install: bool = False) -> bool:
    """Check and optionally install required Python packages."""
    missing = []
    for pkg in packages:
        try:
            __import__(pkg.split("==")[0])  # Handle pinned versions
        except ImportError:
            missing.append(pkg)
    
    if not missing:
        return True
    
    logger.info(f"Missing packages: {', '.join(missing)}")
    if not auto_install:
        logger.warning("Auto-install disabled. Please install manually: pip install " + " ".join(missing))
        return False
    
    confirm = input("[Installer] Attempt to install via pip? (y/n): ").strip().lower()
    if confirm != 'y':
        logger.info("Installation aborted by user.")
        return False
    
    py_exec = sys.executable
    for pkg in missing:
        try:
            subprocess.check_call(
                [py_exec, "-m", "pip", "install", pkg],  # Removed --upgrade --quiet to allow user feedback
                stdout=sys.stdout,  # Redirect to console for visibility
                stderr=sys.stderr
            )
            logger.info(f"✓ {pkg} installed successfully")
        except Exception as e:
            logger.error(f"✗ Failed to install {pkg}: {e}")
            return False
    
    return True

# Safe imports after potential installation
psutil: Optional[Any] = None
wmi: Optional[Any] = None

# =============================================================================
# UTILITIES
# =============================================================================

def run_command(cmd: List[str], timeout: int = 10, shell: bool = False) -> Tuple[int, str, str]:  # Reduced default timeout
    """Execute a command safely and return (returncode, stdout, stderr)."""
    if shell:
        logger.warning("Shell mode enabled for command; potential security risk if inputs unvalidated.")
        cmd_str = " ".join(cmd)
        if any(c in cmd_str for c in [";", "|", "&", "`", "$"]):  # Basic injection check
            raise ValueError("Potential shell injection detected in command.")
        cmd = cmd_str
    
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
            shell=shell,
            check=True  # Raise on non-zero exit
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout.strip(), e.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", f"Command timed out after {timeout}s"
    except Exception as e:
        return 1, "", str(e)

def bytes_to_human(bytes_val: int) -> str:
    """Convert bytes to human-readable format."""
    if bytes_val < 0:
        raise ValueError("Bytes value cannot be negative.")
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.2f} PB"

def safe_get(func, default: Any = None) -> Any:
    """Safely execute a function and return default on error."""
    try:
        return func()
    except Exception as e:
        logger.debug(f"Safe_get error: {e}")
        return default

# =============================================================================
# DATA COLLECTION
# =============================================================================

class SystemCollector:
    """Main system information collector."""
    
    def __init__(self):
        self.data: Dict[str, Any] = {}
        self.errors: List[str] = []
        self.os_type = platform.system().lower()  # Normalized
    
    def collect_all(self) -> Dict[str, Any]:
        """Run all collection methods in order."""
        methods = [
            self.collect_metadata,
            self.collect_os_info,
            self.collect_cpu_info,
            self.collect_memory_info,
            self.collect_disk_info,
            self.collect_gpu_info,
            self.collect_network_info,
            self.collect_processes,
            self.collect_drivers,
            self.collect_software,
            self.collect_power_battery,
            self.collect_sensors
        ]
        for method in methods:
            try:
                method()
            except Exception as e:
                self.log_collection_error(method.__name__, str(e))
        
        self.data["errors"] = sorted(self.errors) if self.errors else []  # Sorted for determinism
        return self.data
    
    def log_collection_error(self, category: str, error: str):
        """Log an error during collection."""
        err_msg = f"[{category}] {error}"
        logger.error(err_msg)
        self.errors.append(err_msg)
    
    def collect_metadata(self):
        """Collect metadata about the report."""
        self.data["metadata"] = {
            "report_version": VERSION,
            "timestamp_utc": datetime.utcnow().isoformat(timespec='seconds') + "Z",  # Simplified
            "timestamp_local": datetime.now().isoformat(timespec='seconds'),
            "hostname": socket.gethostname(),
            "fqdn": safe_get(socket.getfqdn, "unknown"),
            "platform": self.os_type
        }
    
    def collect_os_info(self):
        """Collect OS and kernel information."""
        uname = platform.uname()
        os_data = {
            "system": uname.system,
            "release": uname.release,
            "version": uname.version,
            "machine": uname.machine,
            "processor": platform.processor() or "unknown",
            "python_version": sys.version.split()[0],
            "architecture": platform.architecture()[0]
        }
        
        if self.os_type == "darwin":
            rc, out, err = run_command(["sw_vers"])
            if rc == 0:
                os_data["macos_version"] = out
            else:
                self.log_collection_error("os_darwin", err)
        elif self.os_type == "linux":
            release_file = "/etc/os-release"
            if os.path.isfile(release_file) and os.access(release_file, os.R_OK):
                with open(release_file, "r", encoding="utf-8") as f:
                    os_data["linux_distro"] = f.read().strip()
            else:
                self.log_collection_error("os_linux", f"Cannot read {release_file}")
        
        self.data["os"] = os_data
    
    def collect_cpu_info(self):
        """Collect CPU information."""
        if not psutil:
            self.log_collection_error("cpu", "psutil not available")
            return
        
        cpu_data = {
            "processor": platform.processor() or "unknown",
            "machine": platform.machine(),
            "physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(logical=True),
            "usage_percent": psutil.cpu_percent(interval=0.5)  # Reduced interval for speed
        }
        
        freq = safe_get(psutil.cpu_freq)
        if freq:
            cpu_data["frequency"] = {
                "current_mhz": round(freq.current, 2),
                "min_mhz": round(freq.min or 0, 2),
                "max_mhz": round(freq.max or 0, 2)
            }
        
        if self.os_type == "darwin":
            rc, brand, err = run_command(["sysctl", "-n", "machdep.cpu.brand_string"])
            if rc == 0:
                cpu_data["brand"] = brand.strip()
            else:
                self.log_collection_error("cpu_darwin", err)
        elif self.os_type == "windows" and wmi:
            try:
                c = wmi.WMI()
                for cpu in c.Win32_Processor():
                    cpu_data.update({
                        "brand": cpu.Name,
                        "cores": cpu.NumberOfCores,
                        "logical": cpu.NumberOfLogicalProcessors
                    })
                    break  # Assume single CPU
            except Exception as e:
                self.log_collection_error("cpu_windows", str(e))
        
        self.data["cpu"] = cpu_data
    
    def collect_memory_info(self):
        """Collect memory and swap information."""
        if not psutil:
            self.log_collection_error("memory", "psutil not available")
            return
        
        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        self.data["memory"] = {
            "total": vm.total,
            "total_human": bytes_to_human(vm.total),
            "available": vm.available,
            "available_human": bytes_to_human(vm.available),
            "used": vm.used,
            "used_human": bytes_to_human(vm.used),
            "percent_used": vm.percent,
            "swap": {
                "total": swap.total,
                "total_human": bytes_to_human(swap.total),
                "used": swap.used,
                "used_human": bytes_to_human(swap.used),
                "percent_used": swap.percent
            }
        }
    
    def collect_disk_info(self):
        """Collect disk and partition information."""
        if not psutil:
            self.log_collection_error("disk", "psutil not available")
            return
        
        disks = []
        for partition in psutil.disk_partitions(all=False):
            disk_info = {
                "device": partition.device,
                "mountpoint": partition.mountpoint,
                "fstype": partition.fstype,
                "opts": partition.opts
            }
            
            usage = safe_get(lambda: psutil.disk_usage(partition.mountpoint))
            if usage:
                disk_info.update({
                    "total": usage.total,
                    "total_human": bytes_to_human(usage.total),
                    "used": usage.used,
                    "used_human": bytes_to_human(usage.used),
                    "free": usage.free,
                    "free_human": bytes_to_human(usage.free),
                    "percent_used": usage.percent
                })
            
            disks.append(disk_info)
        
        disk_data = {"partitions": disks}
        
        if self.os_type == "linux" and shutil.which("lsblk"):
            rc, out, err = run_command(["lsblk", "-J", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,MODEL"])
            if rc == 0:
                try:
                    disk_data["lsblk"] = json.loads(out)
                except json.JSONDecodeError as e:
                    self.log_collection_error("disk_linux", f"JSON parse error: {e}")
            else:
                self.log_collection_error("disk_linux", err)
        
        self.data["disk"] = disk_data
    
    def collect_gpu_info(self):
        """Collect GPU information."""
        gpus = []
        
        if self.os_type == "windows" and wmi:
            try:
                c = wmi.WMI()
                for gpu in c.Win32_VideoController():
                    gpus.append({
                        "name": gpu.Name,
                        "ram_bytes": gpu.AdapterRAM,
                        "ram_human": bytes_to_human(gpu.AdapterRAM) if isinstance(gpu.AdapterRAM, int) else str(gpu.AdapterRAM),
                        "driver_version": gpu.DriverVersion,
                        "driver_date": gpu.DriverDate
                    })
            except Exception as e:
                self.log_collection_error("gpu_windows", str(e))
        
        elif self.os_type == "darwin":
            rc, out, err = run_command(["system_profiler", "SPDisplaysDataType", "-json"], timeout=30)
            if rc == 0:
                try:
                    data = json.loads(out)
                    for gpu in data.get("SPDisplaysDataType", []):
                        gpus.append({
                            "name": gpu.get("_name", "Unknown"),
                            "vram": gpu.get("spdisplays_vram", "Unknown"),
                            "metal_supported": gpu.get("spdisplays_metal", "Unknown")
                        })
                except json.JSONDecodeError as e:
                    self.log_collection_error("gpu_darwin", f"JSON parse error: {e}")
            else:
                self.log_collection_error("gpu_darwin", err)
        
        elif self.os_type == "linux":
            if shutil.which("lspci"):
                rc, out, err = run_command(["lspci"])
                if rc == 0:
                    for line in out.splitlines():
                        if any(keyword in line.lower() for keyword in ["vga", "3d", "display"]):
                            gpus.append({"pci_info": line.strip()})
                else:
                    self.log_collection_error("gpu_linux_lspci", err)
            
            if shutil.which("nvidia-smi"):
                rc, out, err = run_command(["nvidia-smi", "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader"])
                if rc == 0:
                    for line in out.splitlines():
                        parts = [p.strip() for p in line.split(",")]
                        if len(parts) == 3:
                            gpus.append({
                                "type": "nvidia",
                                "name": parts[0],
                                "memory": parts[1],
                                "driver": parts[2]
                            })
                else:
                    self.log_collection_error("gpu_linux_nvidia", err)
        
        self.data["gpu"] = {"devices": gpus}
    
    def collect_network_info(self):
        """Collect network interface information."""
        if not psutil:
            self.log_collection_error("network", "psutil not available")
            return
        
        interfaces = []
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        io_counters = safe_get(lambda: psutil.net_io_counters(pernic=True), {})
        
        for name in sorted(addrs):  # Sorted for determinism
            addr_list = addrs[name]
            stat = stats.get(name)
            io = io_counters.get(name)
            
            interface = {
                "name": name,
                "is_up": bool(stat.isup) if stat else False,
                "speed_mbps": stat.speed if stat else None,
                "mtu": stat.mtu if stat else None,
                "addresses": [{"family": str(addr.family), "address": addr.address, "netmask": addr.netmask, "broadcast": addr.broadcast} for addr in addr_list]
            }
            
            if io:
                interface["io"] = {
                    "bytes_sent": io.bytes_sent,
                    "bytes_sent_human": bytes_to_human(io.bytes_sent),
                    "bytes_recv": io.bytes_recv,
                    "bytes_recv_human": bytes_to_human(io.bytes_recv),
                    "packets_sent": io.packets_sent,
                    "packets_recv": io.packets_recv
                }
            
            interfaces.append(interface)
        
        self.data["network"] = {"interfaces": interfaces}
    
    def collect_processes(self):
        """Collect top processes by CPU and memory."""
        if not psutil:
            self.log_collection_error("processes", "psutil not available")
            return
        
        procs = []
        attrs = ["pid", "name", "username", "cpu_percent", "memory_percent"]
        for proc in psutil.process_iter(attrs=attrs, ad_value=None):  # Handle access denied gracefully
            try:
                info = proc.info
                if all(info.get(attr) is not None for attr in attrs):  # Skip incomplete
                    procs.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        top_cpu = sorted(procs, key=lambda x: x["cpu_percent"], reverse=True)[:10]
        top_mem = sorted(procs, key=lambda x: x["memory_percent"], reverse=True)[:10]
        
        self.data["processes"] = {
            "top_cpu": top_cpu,
            "top_memory": top_mem,
            "total_count": len(procs)
        }
    
    def collect_drivers(self):
        """Collect driver/kernel module information."""
        drivers = {}
        
        if self.os_type == "windows":
            ps_cmd = [
                "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-Command",
                "Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName,DriverVersion,Manufacturer | ConvertTo-Json -Compress"
            ]
            rc, out, err = run_command(ps_cmd, timeout=60)  # Reduced timeout
            if rc == 0:
                try:
                    drivers["pnp_signed"] = json.loads(out)[:50]  # Limit to avoid bloat
                except json.JSONDecodeError as e:
                    self.log_collection_error("drivers_windows", f"JSON parse error: {e}")
            else:
                self.log_collection_error("drivers_windows", err)
        
        elif self.os_type == "darwin":
            rc, out, err = run_command(["system_profiler", "SPExtensionsDataType", "-json"], timeout=60)
            if rc == 0:
                try:
                    drivers["kexts"] = json.loads(out)
                except json.JSONDecodeError as e:
                    self.log_collection_error("drivers_darwin", f"JSON parse error: {e}")
            else:
                self.log_collection_error("drivers_darwin", err)
        
        elif self.os_type == "linux" and shutil.which("lsmod"):
            rc, out, err = run_command(["lsmod"])
            if rc == 0:
                drivers["kernel_modules"] = out.splitlines()[1:51]  # Skip header, limit 50
            else:
                self.log_collection_error("drivers_linux", err)
        
        self.data["drivers"] = drivers
    
    def collect_software(self):
        """Collect installed software information."""
        software = {}
        
        if self.os_type == "windows":
            ps_cmd = [
                "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-Command",
                "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName,DisplayVersion,Publisher | ConvertTo-Json -Compress"
            ]
            rc, out, err = run_command(ps_cmd, timeout=120)
            if rc == 0:
                try:
                    software["installed"] = json.loads(out)[:100]  # Limit to avoid bloat
                except json.JSONDecodeError as e:
                    self.log_collection_error("software_windows", f"JSON parse error: {e}")
            else:
                self.log_collection_error("software_windows", err)
        
        elif self.os_type == "darwin":
            rc, out, err = run_command(["system_profiler", "SPApplicationsDataType", "-json"], timeout=120)
            if rc == 0:
                try:
                    data = json.loads(out)
                    software["applications"] = data.get("SPApplicationsDataType", [])[:100]
                except json.JSONDecodeError as e:
                    self.log_collection_error("software_darwin", f"JSON parse error: {e}")
            else:
                self.log_collection_error("software_darwin", err)
        
        elif self.os_type == "linux":
            if shutil.which("dpkg"):
                rc, out, err = run_command(["dpkg", "-l"])
                if rc == 0:
                    software["dpkg_packages"] = [line.split()[1:3] for line in out.splitlines()[5:105]]  # Limit 100
                else:
                    self.log_collection_error("software_linux_dpkg", err)
            elif shutil.which("rpm"):
                rc, out, err = run_command(["rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"])
                if rc == 0:
                    software["rpm_packages"] = out.splitlines()[:100]
                else:
                    self.log_collection_error("software_linux_rpm", err)
        
        self.data["software"] = software
    
    def collect_power_battery(self):
        """Collect power and battery information."""
        power = {}
        
        if psutil and hasattr(psutil, "sensors_battery"):
            battery = safe_get(psutil.sensors_battery)
            if battery:
                power["psutil"] = {
                    "percent": battery.percent,
                    "plugged": battery.power_plugged,
                    "time_left_seconds": battery.secsleft if battery.secsleft != psutil.POWER_TIME_UNLIMITED else None
                }
        
        if self.os_type == "windows" and wmi:
            try:
                c = wmi.WMI()
                for bat in c.Win32_Battery():
                    power["battery"] = {
                        "name": bat.Name,
                        "status": bat.BatteryStatus,
                        "estimated_charge": bat.EstimatedChargeRemaining
                    }
                    break
            except Exception as e:
                self.log_collection_error("power_windows", str(e))
        
        elif self.os_type == "darwin":
            rc, out, err = run_command(["pmset", "-g", "batt"])
            if rc == 0:
                power["battery"] = out.strip()
            else:
                self.log_collection_error("power_darwin", err)
        
        elif self.os_type == "linux" and shutil.which("upower"):
            devices = safe_get(lambda: subprocess.run(["upower", "-e"], capture_output=True, text=True).stdout.splitlines())
            bat_device = next((d for d in devices if "battery" in d.lower()), None) if devices else None
            if bat_device:
                rc, out, err = run_command(["upower", "-i", bat_device])
                if rc == 0:
                    power["battery"] = out.strip()
                else:
                    self.log_collection_error("power_linux", err)
        
        self.data["power"] = power
    
    def collect_sensors(self):
        """Collect temperature sensor information."""
        if not psutil or not hasattr(psutil, "sensors_temperatures"):
            self.log_collection_error("sensors", "psutil sensors not available")
            return
        
        temps = safe_get(psutil.sensors_temperatures)
        if temps:
            self.data["sensors"] = {
                "temperatures": {
                    name: [
                        {"label": t.label, "current": t.current, "high": t.high, "critical": t.critical}
                        for t in temps_list if t.current is not None
                    ]
                    for name, temps_list in temps.items()
                }
            }

# =============================================================================
# OUTPUT WRITERS
# =============================================================================

class OutputWriter:
    """Handle multiple output format generation."""
    
    def __init__(self, data: Dict[str, Any], output_dir: str):
        self.data = data
        self.output_dir = os.path.abspath(output_dir)  # Normalized
        os.makedirs(self.output_dir, exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.hostname = data.get("metadata", {}).get("hostname", "unknown")
    
    def write_all(self) -> List[str]:
        """Generate all output formats."""
        return [
            self.write_json(),
            self.write_yaml(),
            self.write_csv(),
            self.write_html()
        ]
    
    def _get_filename(self, extension: str) -> str:
        """Generate filename with timestamp."""
        base = f"system_health_{self.hostname}_{self.timestamp}.{extension}"
        return os.path.join(self.output_dir, base)
    
    def write_json(self) -> str:
        """Write JSON output."""
        filepath = self._get_filename("json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False, sort_keys=True)  # Sorted for determinism
        return filepath
    
    def write_yaml(self) -> str:
        """Write YAML output using safe recursion with depth limit."""
        filepath = self._get_filename("yaml")
        with open(filepath, "w", encoding="utf-8") as f:
            self._write_yaml_recursive(f, self.data, 0, max_depth=10)  # Added depth limit
        return filepath
    
    def _write_yaml_recursive(self, f, obj: Any, indent_level: int, max_depth: int):
        """Recursively write YAML structure with depth protection."""
        if indent_level > max_depth:
            f.write(f"{'  ' * indent_level}... [truncated]\n")
            return
        
        indent = "  " * indent_level
        if isinstance(obj, dict):
            for key in sorted(obj):  # Sorted for determinism
                value = obj[key]
                f.write(f"{indent}{key}:\n")
                self._write_yaml_recursive(f, value, indent_level + 1, max_depth)
        elif isinstance(obj, list):
            for item in obj:
                f.write(f"{indent}-\n")
                self._write_yaml_recursive(f, item, indent_level + 1, max_depth)
        else:
            safe_value = str(obj).replace("\n", "\\n").replace('"', '\\"')
            f.write(f"{indent}{safe_value}\n")
    
    def write_csv(self) -> str:
        """Write CSV output with flattened structure."""
        filepath = self._get_filename("csv")
        rows = []
        self._flatten_to_rows(rows, "", self.data)
        
        with open(filepath, "w", newline='', encoding="utf-8-sig") as f:  # UTF-8 BOM for Windows
            writer = csv.writer(f)
            writer.writerow(["category", "key", "name", "value", "type"])
            writer.writerows(sorted(rows))  # Sorted for determinism
        
        return filepath
    
    def _flatten_to_rows(self, rows: List[List[str]], prefix: str, obj: Any):
        """Flatten nested structure to CSV rows."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                new_prefix = f"{prefix}.{key}" if prefix else key
                if isinstance(value, (dict, list)):
                    self._flatten_to_rows(rows, new_prefix, value)
                else:
                    rows.append([
                        prefix.split(".")[0] if prefix else "root",
                        new_prefix,
                        key,
                        str(value),
                        type(value).__name__
                    ])
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                new_prefix = f"{prefix}[{i}]"
                if isinstance(item, (dict, list)):
                    self._flatten_to_rows(rows, new_prefix, item)
                else:
                    rows.append([
                        prefix.split(".")[0] if prefix else "root",
                        new_prefix,
                        f"item_{i}",
                        str(item),
                        type(item).__name__
                    ])
    
    def write_html(self) -> str:
        """Write HTML dashboard with sanitized content."""
        filepath = self._get_filename("html")
        html = self._generate_html_template()
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        return filepath
    
    def _generate_html_template(self) -> str:
        """Generate sanitized HTML."""
        # Sanitize all user-facing strings with html.escape
        safe_hostname = escape(self.hostname)
        safe_timestamp = escape(self.data.get('metadata', {}).get('timestamp_local', 'N/A'))
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self' 'unsafe-inline';">  <!-- Added CSP -->
    <title>System Health Report - {safe_hostname}</title>
    <style>
        /* CSS remains the same, but minified for brevity in output */
        *{{margin:0;padding:0;box-sizing:border-box;}}body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,Cantarell,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);padding:20px;line-height:1.6;}}.container{{max-width:1400px;margin:0 auto;background:white;border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,0.3);overflow:hidden;}}.header{{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;padding:30px;text-align:center;}}.header h1{{font-size:2.5em;margin-bottom:10px;}}.header p{{font-size:1.1em;opacity:0.9;}}.content{{padding:30px;}}.section{{margin-bottom:30px;border:1px solid #e0e0e0;border-radius:8px;overflow:hidden;}}.section-header{{background:#f5f5f5;padding:15px 20px;font-weight:bold;font-size:1.2em;color:#333;cursor:pointer;user-select:none;display:flex;justify-content:space-between;align-items:center;}}.section-header:hover{{background:#ebebeb;}}.section-content{{padding:20px;display:block;}}.section-content.collapsed{{display:none;}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px;}}.card{{background:#f9f9f9;padding:20px;border-radius:8px;border:1px solid #e0e0e0;}}.card h3{{color:#667eea;margin-bottom:10px;font-size:1.1em;}}.metric{{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #e0e0e0;}}.metric:last-child{{border-bottom:none;}}.metric-label{{font-weight:600;color:#666;}}.metric-value{{color:#333;text-align:right;}}.status-good{{color:#10b981;font-weight:bold;}}.status-warning{{color:#f59e0b;font-weight:bold;}}.status-critical{{color:#ef4444;font-weight:bold;}}pre{{background:#2d2d2d;color:#f8f8f2;padding:15px;border-radius:6px;overflow-x:auto;font-size:0.9em;}}table{{width:100%;border-collapse:collapse;margin-top:10px;}}th,td{{padding:10px;text-align:left;border-bottom:1px solid #e0e0e0;}}th{{background:#f5f5f5;font-weight:600;color:#333;}}tr:hover{{background:#f9f9f9;}}.toggle-icon{{transition:transform 0.3s;}}.toggle-icon.collapsed{{transform:rotate(-90deg);}}.footer{{background:#f5f5f5;padding:20px;text-align:center;color:#666;border-top:1px solid #e0e0e0;}}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🖥️ System Health Report</h1>
            <p>{safe_hostname} - {safe_timestamp}</p>
        </div>
        
        <div class="content">
            {self._generate_summary_section()}
            {self._generate_os_section()}
            {self._generate_cpu_section()}
            {self._generate_memory_section()}
            {self._generate_disk_section()}
            {self._generate_gpu_section()}
            {self._generate_network_section()}
            {self._generate_processes_section()}
            {self._generate_power_section()}
            {self._generate_errors_section()}
        </div>
        
        <div class="footer">
            <p>Generated by System Health Reporter v{VERSION} | memarzade-dev</p>
        </div>
    </div>
    
    <script>
        document.querySelectorAll('.section-header').forEach(header => {{
            header.addEventListener('click', () => {{
                const content = header.nextElementSibling;
                const icon = header.querySelector('.toggle-icon');
                content.classList.toggle('collapsed');
                icon.classList.toggle('collapsed');
            }});
        }});
    </script>
</body>
</html>"""
    
    def _generate_summary_section(self) -> str:
        meta = self.data.get("metadata", {})
        os_info = self.data.get("os", {})
        cpu = self.data.get("cpu", {})
        mem = self.data.get("memory", {})
        
        safe_meta_hostname = escape(meta.get('hostname', 'N/A'))
        safe_os_system = escape(os_info.get('system', 'N/A'))
        safe_os_version = escape(os_info.get('version', 'N/A'))
        safe_os_arch = escape(os_info.get('architecture', 'N/A'))
        safe_cpu_proc = escape(cpu.get('processor', 'N/A')[:50])
        safe_cpu_phys = escape(str(cpu.get('physical_cores', 'N/A')))
        safe_cpu_log = escape(str(cpu.get('logical_cores', 'N/A')))
        usage_percent = cpu.get('usage_percent', 0)
        safe_cpu_usage = escape(f"{usage_percent}%")
        status_class_cpu = self._get_status_class(usage_percent, 70, 90)
        
        safe_mem_total = escape(mem.get('total_human', 'N/A'))
        safe_mem_avail = escape(mem.get('available_human', 'N/A'))
        safe_mem_used = escape(mem.get('used_human', 'N/A'))
        mem_percent = mem.get('percent_used', 0)
        safe_mem_usage = escape(f"{mem_percent}%")
        status_class_mem = self._get_status_class(mem_percent, 70, 90)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <span>📊 System Summary</span>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <div class="grid">
                    <div class="card">
                        <h3>System Information</h3>
                        <div class="metric">
                            <span class="metric-label">Hostname:</span>
                            <span class="metric-value">{safe_meta_hostname}</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Platform:</span>
                            <span class="metric-value">{safe_os_system}</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">OS Version:</span>
                            <span class="metric-value">{safe_os_version}</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Architecture:</span>
                            <span class="metric-value">{safe_os_arch}</span>
                        </div>
                    </div>
                    
                    <div class="card">
                        <h3>CPU Overview</h3>
                        <div class="metric">
                            <span class="metric-label">Processor:</span>
                            <span class="metric-value">{safe_cpu_proc}</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Physical Cores:</span>
                            <span class="metric-value">{safe_cpu_phys}</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Logical Cores:</span>
                            <span class="metric-value">{safe_cpu_log}</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Usage:</span>
                            <span class="metric-value {status_class_cpu}">{safe_cpu_usage}</span>
                        </div>
                    </div>
                    
                    <div class="card">
                        <h3>Memory Overview</h3>
                        <div class="metric">
                            <span class="metric-label">Total RAM:</span>
                            <span class="metric-value">{safe_mem_total}</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Available:</span>
                            <span class="metric-value">{safe_mem_avail}</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Used:</span>
                            <span class="metric-value">{safe_mem_used}</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Usage:</span>
                            <span class="metric-value {status_class_mem}">{safe_mem_usage}</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>"""
    
    def _generate_os_section(self) -> str:
        os_info = self.data.get("os", {})
        return f"""
        <div class="section">
            <div class="section-header">
                <span>💻 Operating System</span>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <pre>{escape(json.dumps(os_info, indent=2))}</pre>
            </div>
        </div>"""
    
    def _generate_cpu_section(self) -> str:
        cpu = self.data.get("cpu", {})
        return f"""
        <div class="section">
            <div class="section-header">
                <span>⚡ CPU Details</span>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <pre>{escape(json.dumps(cpu, indent=2))}</pre>
            </div>
        </div>"""
    
    def _generate_memory_section(self) -> str:
        mem = self.data.get("memory", {})
        return f"""
        <div class="section">
            <div class="section-header">
                <span>🧠 Memory & Swap</span>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <pre>{escape(json.dumps(mem, indent=2))}</pre>
            </div>
        </div>"""
    
    def _generate_disk_section(self) -> str:
        disk = self.data.get("disk", {})
        partitions = disk.get("partitions", [])
        
        table_rows = ""
        for part in partitions:
            safe_device = escape(part.get('device', 'N/A'))
            safe_mount = escape(part.get('mountpoint', 'N/A'))
            safe_fstype = escape(part.get('fstype', 'N/A'))
            safe_total = escape(part.get('total_human', 'N/A'))
            safe_used = escape(part.get('used_human', 'N/A'))
            safe_free = escape(part.get('free_human', 'N/A'))
            percent = part.get('percent_used', 0)
            safe_percent = escape(f"{percent}%")
            status_class = self._get_status_class(percent, 70, 90)
            table_rows += f"""
                <tr>
                    <td>{safe_device}</td>
                    <td>{safe_mount}</td>
                    <td>{safe_fstype}</td>
                    <td>{safe_total}</td>
                    <td>{safe_used}</td>
                    <td>{safe_free}</td>
                    <td class="{status_class}">{safe_percent}</td>
                </tr>"""
        
        return f"""
        <div class="section">
            <div class="section-header">
                <span>💾 Disk Storage</span>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <table>
                    <thead>
                        <tr>
                            <th>Device</th>
                            <th>Mount Point</th>
                            <th>FS Type</th>
                            <th>Total</th>
                            <th>Used</th>
                            <th>Free</th>
                            <th>Usage %</th>
                        </tr>
                    </thead>
                    <tbody>
                        {table_rows}
                    </tbody>
                </table>
            </div>
        </div>"""
    
    def _generate_gpu_section(self) -> str:
        gpu = self.data.get("gpu", {})
        return f"""
        <div class="section">
            <div class="section-header">
                <span>🎮 Graphics Processing</span>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <pre>{escape(json.dumps(gpu, indent=2))}</pre>
            </div>
        </div>"""
    
    def _generate_network_section(self) -> str:
        net = self.data.get("network", {})
        interfaces = net.get("interfaces", [])
        
        cards = ""
        for iface in interfaces:
            safe_name = escape(iface.get('name', 'Unknown'))
            is_up = iface.get('is_up', False)
            status_class = "status-good" if is_up else "status-critical"
            safe_status = escape('UP' if is_up else 'DOWN')
            safe_speed = escape(str(iface.get('speed_mbps', 'N/A')))
            safe_mtu = escape(str(iface.get('mtu', 'N/A')))
            safe_sent = escape(iface.get('io', {}).get('bytes_sent_human', 'N/A'))
            safe_recv = escape(iface.get('io', {}).get('bytes_recv_human', 'N/A'))
            cards += f"""
                <div class="card">
                    <h3>{safe_name}</h3>
                    <div class="metric">
                        <span class="metric-label">Status:</span>
                        <span class="metric-value {status_class}">{safe_status}</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Speed:</span>
                        <span class="metric-value">{safe_speed} Mbps</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">MTU:</span>
                        <span class="metric-value">{safe_mtu}</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Sent:</span>
                        <span class="metric-value">{safe_sent}</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Received:</span>
                        <span class="metric-value">{safe_recv}</span>
                    </div>
                </div>"""
        
        return f"""
        <div class="section">
            <div class="section-header">
                <span>🌐 Network Interfaces</span>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <div class="grid">
                    {cards}
                </div>
            </div>
        </div>"""
    
    def _generate_processes_section(self) -> str:
        procs = self.data.get("processes", {})
        top_cpu = procs.get("top_cpu", [])[:10]
        top_mem = procs.get("top_memory", [])[:10]
        
        cpu_rows = ""
        for proc in top_cpu:
            safe_pid = escape(str(proc.get('pid', 'N/A')))
            safe_name = escape(proc.get('name', 'N/A'))
            safe_user = escape(proc.get('username', 'N/A'))
            safe_cpu = escape(f"{proc.get('cpu_percent', 'N/A')}%")
            safe_mem = escape(f"{proc.get('memory_percent', 'N/A')}%")
            cpu_rows += f"""
                <tr>
                    <td>{safe_pid}</td>
                    <td>{safe_name}</td>
                    <td>{safe_user}</td>
                    <td>{safe_cpu}</td>
                    <td>{safe_mem}</td>
                </tr>"""
        
        mem_rows = ""
        for proc in top_mem:
            safe_pid = escape(str(proc.get('pid', 'N/A')))
            safe_name = escape(proc.get('name', 'N/A'))
            safe_user = escape(proc.get('username', 'N/A'))
            safe_cpu = escape(f"{proc.get('cpu_percent', 'N/A')}%")
            safe_mem = escape(f"{proc.get('memory_percent', 'N/A')}%")
            mem_rows += f"""
                <tr>
                    <td>{safe_pid}</td>
                    <td>{safe_name}</td>
                    <td>{safe_user}</td>
                    <td>{safe_cpu}</td>
                    <td>{safe_mem}</td>
                </tr>"""
        
        return f"""
        <div class="section">
            <div class="section-header">
                <span>📈 Top Processes</span>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <h3>Top 10 by CPU Usage</h3>
                <table>
                    <thead>
                        <tr>
                            <th>PID</th>
                            <th>Name</th>
                            <th>User</th>
                            <th>CPU %</th>
                            <th>Memory %</th>
                        </tr>
                    </thead>
                    <tbody>
                        {cpu_rows}
                    </tbody>
                </table>
                
                <h3 style="margin-top: 30px;">Top 10 by Memory Usage</h3>
                <table>
                    <thead>
                        <tr>
                            <th>PID</th>
                            <th>Name</th>
                            <th>User</th>
                            <th>CPU %</th>
                            <th>Memory %</th>
                        </tr>
                    </thead>
                    <tbody>
                        {mem_rows}
                    </tbody>
                </table>
            </div>
        </div>"""
    
    def _generate_power_section(self) -> str:
        power = self.data.get("power", {})
        if not power:
            return ""
        
        return f"""
        <div class="section">
            <div class="section-header">
                <span>🔋 Power & Battery</span>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <pre>{escape(json.dumps(power, indent=2))}</pre>
            </div>
        </div>"""
    
    def _generate_errors_section(self) -> str:
        errors = self.data.get("errors", [])
        if not errors:
            return """
        <div class="section">
            <div class="section-header">
                <span>✅ Status</span>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <p class="status-good">No errors encountered during data collection.</p>
            </div>
        </div>"""
        
        error_items = "".join([f"<li>{escape(err)}</li>" for err in errors])
        return f"""
        <div class="section">
            <div class="section-header">
                <span>⚠️ Errors</span>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <ul style="color: #ef4444; padding-left: 20px;">
                    {error_items}
                </ul>
            </div>
        </div>"""
    
    def _get_status_class(self, value: float, warning: float, critical: float) -> str:
        """Get CSS class based on threshold."""
        if not isinstance(value, (int, float)):
            return ""
        if value >= critical:
            return "status-critical"
        elif value >= warning:
            return "status-warning"
        return "status-good"

# =============================================================================
# MAIN CLI
# =============================================================================

def main():
    """Main entry point."""
    print(f"\n{'='*70}")
    print(f"  System Health Reporter v{VERSION}")
    print(f"  Author: memarzade-dev")
    print(f"{'='*70}\n")
    
    # Parse arguments with validation
    output_dir = DEFAULT_OUTPUT_DIR
    auto_install = False
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            if arg == "--auto-install":
                auto_install = True
            elif os.path.isdir(arg) or os.access(os.path.dirname(arg), os.W_OK):
                output_dir = arg
            else:
                logger.error(f"Invalid argument: {arg}")
                sys.exit(1)
    
    if not ensure_dependencies(REQUIRED_PACKAGES, auto_install):
        logger.error("Failed to ensure dependencies. Exiting.")
        sys.exit(1)
    
    global psutil, wmi  # Load after ensure
    try:
        import psutil
    except ImportError:
        psutil = None
    if platform.system() == "Windows":
        try:
            import wmi
        except ImportError:
            wmi = None
    
    print(f"[1/3] Collecting system information...")
    collector = SystemCollector()
    data = collector.collect_all()
    
    print(f"[2/3] Generating reports...")
    writer = OutputWriter(data, output_dir)
    files = writer.write_all()
    
    print(f"[3/3] Reports generated successfully!\n")
    print(f"Output directory: {output_dir}\n")
    print("Generated files:")
    for filepath in sorted(files):  # Sorted
        filesize = os.path.getsize(filepath)
        print(f"  • {os.path.basename(filepath)} ({bytes_to_human(filesize)})")
    
    print(f"\n{'='*70}")
    print(f"✅ System health audit complete!")
    print(f"{'='*70}\n")
    
    # Open HTML report if possible and safe
    html_file = next((f for f in files if f.endswith('.html')), None)
    if html_file:
        print(f"💡 Tip: Open the HTML report in your browser:")
        print(f"   {html_file}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Exiting...")
        sys.exit(130)
    except Exception as e:
        logger.critical(f"[FATAL ERROR] {e}")
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
