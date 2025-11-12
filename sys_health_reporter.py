#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
System Health Reporter
======================
Cross-platform system monitoring and reporting tool for Windows, macOS, and Linux.
Generates comprehensive health reports in multiple formats (CSV, JSON, YAML, HTML).

Author: memarzade-dev
License: MIT
Python: 3.7+

Features:
- Auto-installs dependencies (psutil, wmi on Windows)
- Collects hardware, OS, CPU, memory, disk, GPU, network, processes
- Driver enumeration and installed software inventory
- Battery/power status and temperature sensors
- Multiple output formats with rich HTML dashboard
- No admin required (degrades gracefully)
"""

from __future__ import annotations
import csv
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

# =============================================================================
# CONSTANTS
# =============================================================================

VERSION = "1.0.0"
DEFAULT_OUTPUT_DIR = os.path.join(os.path.expanduser("~"), "system_health_reports")
REQUIRED_PACKAGES = ["psutil"]
if platform.system() == "Windows":
    REQUIRED_PACKAGES.append("wmi")

# =============================================================================
# DEPENDENCY INSTALLER
# =============================================================================

def ensure_dependencies(packages: List[str]) -> bool:
    """Install required Python packages if missing."""
    missing = []
    for pkg in packages:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    
    if not missing:
        return True
    
    print(f"[Installer] Missing packages: {', '.join(missing)}")
    print("[Installer] Attempting to install via pip...")
    
    py_exec = sys.executable
    for pkg in missing:
        try:
            subprocess.check_call(
                [py_exec, "-m", "pip", "install", "--upgrade", "--quiet", pkg],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print(f"[Installer] ✓ {pkg} installed successfully")
        except Exception as e:
            print(f"[Installer] ✗ Failed to install {pkg}: {e}")
            print(f"[Installer] Please install manually: pip install {pkg}")
            return False
    
    return True

# Install dependencies before importing
if not ensure_dependencies(REQUIRED_PACKAGES):
    print("\n[ERROR] Failed to install required dependencies. Exiting.")
    sys.exit(1)

# Safe imports after installation
try:
    import psutil
except ImportError:
    psutil = None

try:
    import wmi
except ImportError:
    wmi = None

# =============================================================================
# UTILITIES
# =============================================================================

def run_command(cmd: List[str], timeout: int = 30, shell: bool = False) -> Tuple[int, str, str]:
    """Execute a command and return (returncode, stdout, stderr)."""
    try:
        if shell:
            cmd = " ".join(cmd)
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
            shell=shell
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", f"Command timed out after {timeout}s"
    except Exception as e:
        return 1, "", str(e)

def bytes_to_human(bytes_val: int) -> str:
    """Convert bytes to human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.2f} PB"

def safe_get(func, default=None):
    """Safely execute a function and return default on error."""
    try:
        return func()
    except Exception:
        return default

# =============================================================================
# DATA COLLECTION
# =============================================================================

class SystemCollector:
    """Main system information collector."""
    
    def __init__(self):
        self.data: Dict[str, Any] = {}
        self.errors: List[str] = []
        self.os_type = platform.system()
    
    def collect_all(self) -> Dict[str, Any]:
        """Run all collection methods."""
        self.collect_metadata()
        self.collect_os_info()
        self.collect_cpu_info()
        self.collect_memory_info()
        self.collect_disk_info()
        self.collect_gpu_info()
        self.collect_network_info()
        self.collect_processes()
        self.collect_drivers()
        self.collect_software()
        self.collect_power_battery()
        self.collect_sensors()
        
        self.data["errors"] = self.errors if self.errors else []
        return self.data
    
    def _add_error(self, category: str, error: str):
        """Log an error during collection."""
        self.errors.append(f"[{category}] {error}")
    
    def collect_metadata(self):
        """Collect metadata about the report."""
        self.data["metadata"] = {
            "report_version": VERSION,
            "timestamp_utc": datetime.utcnow().isoformat() + "Z",
            "timestamp_local": datetime.now().isoformat(),
            "hostname": socket.gethostname(),
            "fqdn": safe_get(socket.getfqdn, "unknown"),
            "platform": self.os_type
        }
    
    def collect_os_info(self):
        """Collect OS and kernel information."""
        try:
            uname = platform.uname()
            self.data["os"] = {
                "system": uname.system,
                "release": uname.release,
                "version": uname.version,
                "machine": uname.machine,
                "processor": platform.processor(),
                "python_version": sys.version.split()[0],
                "architecture": platform.architecture()[0]
            }
            
            if self.os_type == "Darwin":
                rc, out, _ = run_command(["sw_vers"])
                if rc == 0:
                    self.data["os"]["macos_version"] = out
            elif self.os_type == "Linux":
                if os.path.exists("/etc/os-release"):
                    with open("/etc/os-release", "r") as f:
                        self.data["os"]["linux_distro"] = f.read().strip()
        except Exception as e:
            self._add_error("os", str(e))
    
    def collect_cpu_info(self):
        """Collect CPU information."""
        try:
            cpu_data = {
                "processor": platform.processor(),
                "machine": platform.machine()
            }
            
            if psutil:
                cpu_data.update({
                    "physical_cores": psutil.cpu_count(logical=False),
                    "logical_cores": psutil.cpu_count(logical=True),
                    "usage_percent": psutil.cpu_percent(interval=1.0)
                })
                
                freq = safe_get(psutil.cpu_freq)
                if freq:
                    cpu_data["frequency"] = {
                        "current_mhz": round(freq.current, 2),
                        "min_mhz": round(freq.min or 0, 2),
                        "max_mhz": round(freq.max or 0, 2)
                    }
            
            if self.os_type == "Darwin":
                rc, brand, _ = run_command(["sysctl", "-n", "machdep.cpu.brand_string"])
                if rc == 0:
                    cpu_data["brand"] = brand
            elif self.os_type == "Windows":
                rc, out, _ = run_command([
                    "wmic", "cpu", "get", 
                    "Name,NumberOfCores,NumberOfLogicalProcessors", 
                    "/format:csv"
                ])
                if rc == 0 and out:
                    lines = [l.strip() for l in out.splitlines() if l.strip()][1:]
                    if lines:
                        parts = lines[0].split(",")
                        if len(parts) >= 4:
                            cpu_data["windows_cpu"] = {
                                "name": parts[2],
                                "cores": parts[1],
                                "logical": parts[3]
                            }
            
            self.data["cpu"] = cpu_data
        except Exception as e:
            self._add_error("cpu", str(e))
    
    def collect_memory_info(self):
        """Collect memory and swap information."""
        try:
            if not psutil:
                self.data["memory"] = {"status": "psutil not available"}
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
        except Exception as e:
            self._add_error("memory", str(e))
    
    def collect_disk_info(self):
        """Collect disk and partition information."""
        try:
            disks = []
            
            if psutil:
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
            
            if self.os_type == "Linux":
                rc, out, _ = run_command([
                    "lsblk", "-J", "-o", 
                    "NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,MODEL"
                ])
                if rc == 0 and out:
                    try:
                        lsblk_data = json.loads(out)
                        self.data["disk"] = {
                            "partitions": disks,
                            "lsblk": lsblk_data
                        }
                        return
                    except json.JSONDecodeError:
                        pass
            
            self.data["disk"] = {"partitions": disks}
        except Exception as e:
            self._add_error("disk", str(e))
    
    def collect_gpu_info(self):
        """Collect GPU information."""
        try:
            gpus = []
            
            if self.os_type == "Windows":
                rc, out, _ = run_command([
                    "wmic", "path", "win32_VideoController", "get",
                    "Name,AdapterRAM,DriverVersion,DriverDate", "/format:csv"
                ])
                if rc == 0 and out:
                    lines = [l.strip() for l in out.splitlines() if l.strip()][1:]
                    for line in lines:
                        parts = [p.strip() for p in line.split(",")]
                        if len(parts) >= 5:
                            gpus.append({
                                "name": parts[2],
                                "ram_bytes": parts[1],
                                "ram_human": bytes_to_human(int(parts[1])) if parts[1].isdigit() else parts[1],
                                "driver_version": parts[3],
                                "driver_date": parts[4]
                            })
            
            elif self.os_type == "Darwin":
                rc, out, _ = run_command([
                    "system_profiler", "SPDisplaysDataType", "-json"
                ], timeout=60)
                if rc == 0 and out:
                    try:
                        data = json.loads(out)
                        for gpu in data.get("SPDisplaysDataType", []):
                            gpus.append({
                                "name": gpu.get("_name", "Unknown"),
                                "vram": gpu.get("spdisplays_vram", "Unknown"),
                                "metal_supported": gpu.get("spdisplays_metal", "Unknown"),
                                "raw": gpu
                            })
                    except json.JSONDecodeError:
                        pass
            
            else:  # Linux
                rc, out, _ = run_command(
                    ["bash", "-c", "lspci | grep -iE 'vga|3d|display' || true"],
                    shell=True
                )
                if out:
                    for i, line in enumerate(out.splitlines()):
                        gpus.append({"id": i, "pci_info": line})
                
                if shutil.which("nvidia-smi"):
                    rc, out, _ = run_command([
                        "nvidia-smi",
                        "--query-gpu=name,memory.total,driver_version",
                        "--format=csv,noheader"
                    ])
                    if rc == 0 and out:
                        for i, line in enumerate(out.splitlines()):
                            parts = [p.strip() for p in line.split(",")]
                            if len(parts) >= 3:
                                gpus.append({
                                    "type": "nvidia",
                                    "name": parts[0],
                                    "memory": parts[1],
                                    "driver": parts[2]
                                })
            
            self.data["gpu"] = {"devices": gpus}
        except Exception as e:
            self._add_error("gpu", str(e))
    
    def collect_network_info(self):
        """Collect network interface information."""
        try:
            if not psutil:
                self.data["network"] = {"status": "psutil not available"}
                return
            
            interfaces = []
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            io_counters = safe_get(lambda: psutil.net_io_counters(pernic=True), {})
            
            for name, addr_list in addrs.items():
                stat = stats.get(name)
                io = io_counters.get(name)
                
                interface = {
                    "name": name,
                    "is_up": stat.isup if stat else False,
                    "speed_mbps": stat.speed if stat else None,
                    "mtu": stat.mtu if stat else None,
                    "addresses": []
                }
                
                for addr in addr_list:
                    interface["addresses"].append({
                        "family": str(addr.family),
                        "address": addr.address,
                        "netmask": getattr(addr, "netmask", None),
                        "broadcast": getattr(addr, "broadcast", None)
                    })
                
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
        except Exception as e:
            self._add_error("network", str(e))
    
    def collect_processes(self):
        """Collect top processes by CPU and memory."""
        try:
            if not psutil:
                self.data["processes"] = {"status": "psutil not available"}
                return
            
            procs = []
            for proc in psutil.process_iter(attrs=["pid", "name", "username", "cpu_percent", "memory_percent"]):
                try:
                    info = proc.info
                    if info:
                        procs.append(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            top_cpu = sorted(
                procs,
                key=lambda x: x.get("cpu_percent", 0),
                reverse=True
            )[:10]
            
            top_mem = sorted(
                procs,
                key=lambda x: x.get("memory_percent", 0),
                reverse=True
            )[:10]
            
            self.data["processes"] = {
                "top_cpu": top_cpu,
                "top_memory": top_mem,
                "total_count": len(procs)
            }
        except Exception as e:
            self._add_error("processes", str(e))
    
    def collect_drivers(self):
        """Collect driver/kernel module information."""
        try:
            drivers = {}
            
            if self.os_type == "Windows":
                ps_cmd = [
                    "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-Command",
                    "Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName,DriverVersion,Manufacturer | ConvertTo-Json"
                ]
                rc, out, _ = run_command(ps_cmd, timeout=120)
                if rc == 0 and out:
                    try:
                        drivers["pnp_signed"] = json.loads(out)
                    except json.JSONDecodeError:
                        drivers["pnp_signed"] = "parse_error"
            
            elif self.os_type == "Darwin":
                rc, out, _ = run_command([
                    "system_profiler", "SPExtensionsDataType", "-json"
                ], timeout=120)
                if rc == 0 and out:
                    try:
                        drivers["kexts"] = json.loads(out)
                    except json.JSONDecodeError:
                        drivers["kexts"] = "parse_error"
            
            else:  # Linux
                rc, out, _ = run_command(["lsmod"])
                if rc == 0:
                    drivers["kernel_modules"] = out.splitlines()[:50]  # First 50 modules
            
            self.data["drivers"] = drivers
        except Exception as e:
            self._add_error("drivers", str(e))
    
    def collect_software(self):
        """Collect installed software information."""
        try:
            software = {}
            
            if self.os_type == "Windows":
                ps_cmd = [
                    "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-Command",
                    "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
                    "Select-Object DisplayName,DisplayVersion,Publisher | ConvertTo-Json"
                ]
                rc, out, _ = run_command(ps_cmd, timeout=180)
                if rc == 0 and out:
                    try:
                        software["installed"] = json.loads(out)
                    except json.JSONDecodeError:
                        software["installed"] = "parse_error"
            
            elif self.os_type == "Darwin":
                rc, out, _ = run_command([
                    "system_profiler", "SPApplicationsDataType", "-json"
                ], timeout=180)
                if rc == 0 and out:
                    try:
                        data = json.loads(out)
                        apps = data.get("SPApplicationsDataType", [])
                        software["applications"] = apps[:100]  # First 100 apps
                    except json.JSONDecodeError:
                        software["applications"] = "parse_error"
            
            else:  # Linux
                if shutil.which("dpkg"):
                    rc, out, _ = run_command(
                        ["bash", "-c", "dpkg -l | awk 'NR>5 {print $2, $3}' | head -n 100"],
                        shell=True
                    )
                    if rc == 0:
                        software["dpkg_packages"] = out.splitlines()
                
                elif shutil.which("rpm"):
                    rc, out, _ = run_command(
                        ["bash", "-c", "rpm -qa --qf '%{NAME} %{VERSION}\\n' | head -n 100"],
                        shell=True
                    )
                    if rc == 0:
                        software["rpm_packages"] = out.splitlines()
            
            self.data["software"] = software
        except Exception as e:
            self._add_error("software", str(e))
    
    def collect_power_battery(self):
        """Collect power and battery information."""
        try:
            power = {}
            
            if self.os_type == "Windows":
                rc, out, _ = run_command([
                    "wmic", "path", "Win32_Battery", "get", "*", "/format:csv"
                ])
                if rc == 0 and out:
                    power["battery"] = out
            
            elif self.os_type == "Darwin":
                rc, out, _ = run_command(["pmset", "-g", "batt"])
                if rc == 0:
                    power["battery"] = out
                
                rc, out, _ = run_command(["pmset", "-g", "assertions"])
                if rc == 0:
                    power["assertions"] = out
            
            else:  # Linux
                rc, out, _ = run_command(
                    ["bash", "-c", "upower -i $(upower -e | grep BAT | head -n1) 2>/dev/null || true"],
                    shell=True
                )
                if out:
                    power["battery"] = out
            
            if psutil and hasattr(psutil, "sensors_battery"):
                battery = safe_get(psutil.sensors_battery)
                if battery:
                    power["psutil"] = {
                        "percent": battery.percent,
                        "plugged": battery.power_plugged,
                        "time_left_seconds": battery.secsleft if battery.secsleft != psutil.POWER_TIME_UNLIMITED else None
                    }
            
            self.data["power"] = power
        except Exception as e:
            self._add_error("power", str(e))
    
    def collect_sensors(self):
        """Collect temperature sensor information."""
        try:
            sensors = {}
            
            if psutil and hasattr(psutil, "sensors_temperatures"):
                temps = safe_get(psutil.sensors_temperatures)
                if temps:
                    sensors["temperatures"] = {
                        name: [
                            {
                                "label": t.label,
                                "current": t.current,
                                "high": t.high,
                                "critical": t.critical
                            }
                            for t in temps_list
                        ]
                        for name, temps_list in temps.items()
                    }
            
            self.data["sensors"] = sensors
        except Exception as e:
            self._add_error("sensors", str(e))

# =============================================================================
# OUTPUT WRITERS
# =============================================================================

class OutputWriter:
    """Handle multiple output format generation."""
    
    def __init__(self, data: Dict[str, Any], output_dir: str):
        self.data = data
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.hostname = data.get("metadata", {}).get("hostname", "unknown")
    
    def write_all(self):
        """Generate all output formats."""
        files = []
        files.append(self.write_json())
        files.append(self.write_yaml())
        files.append(self.write_csv())
        files.append(self.write_html())
        return files
    
    def _get_filename(self, extension: str) -> str:
        """Generate filename with timestamp."""
        return os.path.join(
            self.output_dir,
            f"system_health_{self.hostname}_{self.timestamp}.{extension}"
        )
    
    def write_json(self) -> str:
        """Write JSON output."""
        filepath = self._get_filename("json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)
        return filepath
    
    def write_yaml(self) -> str:
        """Write YAML output."""
        filepath = self._get_filename("yaml")
        with open(filepath, "w", encoding="utf-8") as f:
            self._write_yaml_recursive(f, self.data, 0)
        return filepath
    
    def _write_yaml_recursive(self, f, obj, indent_level):
        """Recursively write YAML structure."""
        indent = "  " * indent_level
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, (dict, list)):
                    f.write(f"{indent}{key}:\n")
                    self._write_yaml_recursive(f, value, indent_level + 1)
                else:
                    safe_value = str(value).replace('"', '\\"')
                    if ":" in safe_value or "\n" in safe_value:
                        f.write(f'{indent}{key}: "{safe_value}"\n')
                    else:
                        f.write(f"{indent}{key}: {safe_value}\n")
        
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    f.write(f"{indent}-\n")
                    self._write_yaml_recursive(f, item, indent_level + 1)
                else:
                    f.write(f"{indent}- {item}\n")
    
    def write_csv(self) -> str:
        """Write CSV output with flattened structure."""
        filepath = self._get_filename("csv")
        rows = []
        self._flatten_to_rows(rows, "", self.data)
        
        with open(filepath, "w", newline='', encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["category", "key", "name", "value", "type"])
            writer.writerows(rows)
        
        return filepath
    
    def _flatten_to_rows(self, rows, prefix, obj):
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
        """Write HTML dashboard."""
        filepath = self._get_filename("html")
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Health Report - {self.hostname}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header p {{ font-size: 1.1em; opacity: 0.9; }}
        .content {{ padding: 30px; }}
        .section {{
            margin-bottom: 30px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            overflow: hidden;
        }}
        .section-header {{
            background: #f5f5f5;
            padding: 15px 20px;
            font-weight: bold;
            font-size: 1.2em;
            color: #333;
            cursor: pointer;
            user-select: none;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .section-header:hover {{ background: #ebebeb; }}
        .section-content {{
            padding: 20px;
            display: block;
        }}
        .section-content.collapsed {{ display: none; }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }}
        .card {{
            background: #f9f9f9;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #e0e0e0;
        }}
        .card h3 {{
            color: #667eea;
            margin-bottom: 10px;
            font-size: 1.1em;
        }}
        .metric {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #e0e0e0;
        }}
        .metric:last-child {{ border-bottom: none; }}
        .metric-label {{ font-weight: 600; color: #666; }}
        .metric-value {{ color: #333; text-align: right; }}
        .status-good {{ color: #10b981; font-weight: bold; }}
        .status-warning {{ color: #f59e0b; font-weight: bold; }}
        .status-critical {{ color: #ef4444; font-weight: bold; }}
        pre {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 0.9em;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th, td {{
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }}
        th {{
            background: #f5f5f5;
            font-weight: 600;
            color: #333;
        }}
        tr:hover {{ background: #f9f9f9; }}
        .toggle-icon {{ transition: transform 0.3s; }}
        .toggle-icon.collapsed {{ transform: rotate(-90deg); }}
        .footer {{
            background: #f5f5f5;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #e0e0e0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🖥️ System Health Report</h1>
            <p>{self.hostname} - {self.data.get('metadata', {}).get('timestamp_local', 'N/A')}</p>
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
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        
        return filepath
    
    def _generate_summary_section(self) -> str:
        """Generate summary section HTML."""
        meta = self.data.get("metadata", {})
        os_info = self.data.get("os", {})
        cpu = self.data.get("cpu", {})
        mem = self.data.get("memory", {})
        
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
                            <span class="metric-value">{meta.get('hostname', 'N/A')}</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Platform:</span>
                            <span class="metric-value">{os_info.get('system', 'N/A')}</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">OS Version:</span>
                            <span class="metric-value">{os_info.get('version', 'N/A')}</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Architecture:</span>
                            <span class="metric-value">{os_info.get('architecture', 'N/A')}</span>
                        </div>
                    </div>
                    
                    <div class="card">
                        <h3>CPU Overview</h3>
                        <div class="metric">
                            <span class="metric-label">Processor:</span>
                            <span class="metric-value">{cpu.get('processor', 'N/A')[:50]}</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Physical Cores:</span>
                            <span class="metric-value">{cpu.get('physical_cores', 'N/A')}</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Logical Cores:</span>
                            <span class="metric-value">{cpu.get('logical_cores', 'N/A')}</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Usage:</span>
                            <span class="metric-value {self._get_status_class(cpu.get('usage_percent', 0), 70, 90)}">
                                {cpu.get('usage_percent', 'N/A')}%
                            </span>
                        </div>
                    </div>
                    
                    <div class="card">
                        <h3>Memory Overview</h3>
                        <div class="metric">
                            <span class="metric-label">Total RAM:</span>
                            <span class="metric-value">{mem.get('total_human', 'N/A')}</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Available:</span>
                            <span class="metric-value">{mem.get('available_human', 'N/A')}</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Used:</span>
                            <span class="metric-value">{mem.get('used_human', 'N/A')}</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Usage:</span>
                            <span class="metric-value {self._get_status_class(mem.get('percent_used', 0), 70, 90)}">
                                {mem.get('percent_used', 'N/A')}%
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        </div>"""
    
    def _generate_os_section(self) -> str:
        """Generate OS section HTML."""
        os_info = self.data.get("os", {})
        return f"""
        <div class="section">
            <div class="section-header">
                <span>💻 Operating System</span>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <pre>{json.dumps(os_info, indent=2)}</pre>
            </div>
        </div>"""
    
    def _generate_cpu_section(self) -> str:
        """Generate CPU section HTML."""
        cpu = self.data.get("cpu", {})
        return f"""
        <div class="section">
            <div class="section-header">
                <span>⚡ CPU Details</span>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <pre>{json.dumps(cpu, indent=2)}</pre>
            </div>
        </div>"""
    
    def _generate_memory_section(self) -> str:
        """Generate memory section HTML."""
        mem = self.data.get("memory", {})
        return f"""
        <div class="section">
            <div class="section-header">
                <span>🧠 Memory & Swap</span>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <pre>{json.dumps(mem, indent=2)}</pre>
            </div>
        </div>"""
    
    def _generate_disk_section(self) -> str:
        """Generate disk section HTML."""
        disk = self.data.get("disk", {})
        partitions = disk.get("partitions", [])
        
        table_rows = ""
        for part in partitions:
            table_rows += f"""
                <tr>
                    <td>{part.get('device', 'N/A')}</td>
                    <td>{part.get('mountpoint', 'N/A')}</td>
                    <td>{part.get('fstype', 'N/A')}</td>
                    <td>{part.get('total_human', 'N/A')}</td>
                    <td>{part.get('used_human', 'N/A')}</td>
                    <td>{part.get('free_human', 'N/A')}</td>
                    <td class="{self._get_status_class(part.get('percent_used', 0), 70, 90)}">
                        {part.get('percent_used', 'N/A')}%
                    </td>
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
        """Generate GPU section HTML."""
        gpu = self.data.get("gpu", {})
        return f"""
        <div class="section">
            <div class="section-header">
                <span>🎮 Graphics Processing</span>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <pre>{json.dumps(gpu, indent=2)}</pre>
            </div>
        </div>"""
    
    def _generate_network_section(self) -> str:
        """Generate network section HTML."""
        net = self.data.get("network", {})
        interfaces = net.get("interfaces", [])
        
        cards = ""
        for iface in interfaces:
            status_class = "status-good" if iface.get("is_up") else "status-critical"
            cards += f"""
                <div class="card">
                    <h3>{iface.get('name', 'Unknown')}</h3>
                    <div class="metric">
                        <span class="metric-label">Status:</span>
                        <span class="metric-value {status_class}">
                            {'UP' if iface.get('is_up') else 'DOWN'}
                        </span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Speed:</span>
                        <span class="metric-value">{iface.get('speed_mbps', 'N/A')} Mbps</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">MTU:</span>
                        <span class="metric-value">{iface.get('mtu', 'N/A')}</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Sent:</span>
                        <span class="metric-value">{iface.get('io', {}).get('bytes_sent_human', 'N/A')}</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Received:</span>
                        <span class="metric-value">{iface.get('io', {}).get('bytes_recv_human', 'N/A')}</span>
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
        """Generate processes section HTML."""
        procs = self.data.get("processes", {})
        top_cpu = procs.get("top_cpu", [])
        top_mem = procs.get("top_memory", [])
        
        cpu_rows = ""
        for proc in top_cpu[:10]:
            cpu_rows += f"""
                <tr>
                    <td>{proc.get('pid', 'N/A')}</td>
                    <td>{proc.get('name', 'N/A')}</td>
                    <td>{proc.get('username', 'N/A')}</td>
                    <td>{proc.get('cpu_percent', 'N/A')}%</td>
                    <td>{proc.get('memory_percent', 'N/A')}%</td>
                </tr>"""
        
        mem_rows = ""
        for proc in top_mem[:10]:
            mem_rows += f"""
                <tr>
                    <td>{proc.get('pid', 'N/A')}</td>
                    <td>{proc.get('name', 'N/A')}</td>
                    <td>{proc.get('username', 'N/A')}</td>
                    <td>{proc.get('cpu_percent', 'N/A')}%</td>
                    <td>{proc.get('memory_percent', 'N/A')}%</td>
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
        """Generate power/battery section HTML."""
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
                <pre>{json.dumps(power, indent=2)}</pre>
            </div>
        </div>"""
    
    def _generate_errors_section(self) -> str:
        """Generate errors section HTML."""
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
        
        error_items = "".join([f"<li>{err}</li>" for err in errors])
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
    
    # Parse arguments
    output_dir = DEFAULT_OUTPUT_DIR
    if len(sys.argv) > 1:
        output_dir = sys.argv[1]
    
    print(f"[1/3] Collecting system information...")
    collector = SystemCollector()
    data = collector.collect_all()
    
    print(f"[2/3] Generating reports...")
    writer = OutputWriter(data, output_dir)
    files = writer.write_all()
    
    print(f"[3/3] Reports generated successfully!\n")
    print(f"Output directory: {output_dir}\n")
    print("Generated files:")
    for filepath in files:
        filesize = os.path.getsize(filepath)
        print(f"  • {os.path.basename(filepath)} ({bytes_to_human(filesize)})")
    
    print(f"\n{'='*70}")
    print(f"✅ System health audit complete!")
    print(f"{'='*70}\n")
    
    # Open HTML report if possible
    html_file = [f for f in files if f.endswith('.html')][0]
    print(f"💡 Tip: Open the HTML report in your browser:")
    print(f"   {html_file}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Exiting...")
        sys.exit(130)
    except Exception as e:
        print(f"\n[FATAL ERROR] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)