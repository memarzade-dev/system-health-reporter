# System Health Reporter

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](https://github.com/memarzade-dev)

A comprehensive, production-grade system monitoring and reporting tool that generates detailed health reports for Windows, macOS, and Linux systems. Perfect for system administrators, DevOps engineers, and IT professionals who need detailed system inventories.

## ✨ Features

- **🔄 Cross-Platform**: Works seamlessly on Windows, macOS, and Linux
- **📦 Auto-Installation**: Automatically installs required dependencies (psutil, wmi)
- **📊 Comprehensive Data Collection**:
  - Hardware specifications (CPU, Memory, GPU, Disk)
  - Operating system details and kernel information
  - Network interfaces, IP addresses, and traffic statistics
  - Top processes by CPU and memory usage
  - Driver/kernel module enumeration
  - Installed software inventory
  - Battery/power status (laptops)
  - Temperature sensors (when available)
- **📄 Multiple Output Formats**: JSON, YAML, CSV, and interactive HTML dashboard
- **🎨 Beautiful HTML Reports**: Responsive, collapsible sections with color-coded status indicators
- **🔒 Security-First**: No admin privileges required (degrades gracefully)
- **⚡ Fast & Efficient**: Optimized data collection with configurable timeouts

## 📋 Requirements

- **Python**: 3.7 or higher
- **Dependencies**: Auto-installed on first run
  - `psutil` (cross-platform system utilities)
  - `wmi` (Windows only - for WMI queries)

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/memarzade-dev/system-health-reporter.git
cd system-health-reporter

# Run the script (dependencies will auto-install)
python system_health_reporter.py
```

### Basic Usage

```bash
# Generate reports in default directory (~/system_health_reports)
python system_health_reporter.py

# Specify custom output directory
python system_health_reporter.py /path/to/output/directory

# On Windows
python system_health_reporter.py C:\Reports\SystemHealth
```

## 📖 Usage Examples

### Example 1: Quick System Audit

```bash
python system_health_reporter.py
```

This will generate four files:
- `system_health_<hostname>_<timestamp>.json` - Full data in JSON format
- `system_health_<hostname>_<timestamp>.yaml` - Human-readable YAML format
- `system_health_<hostname>_<timestamp>.csv` - Spreadsheet-compatible CSV
- `system_health_<hostname>_<timestamp>.html` - Interactive dashboard

### Example 2: Automated Daily Reports (Linux/macOS)

Create a cron job to run daily reports:

```bash
# Edit crontab
crontab -e

# Add this line to run daily at 2 AM
0 2 * * * /usr/bin/python3 /path/to/system_health_reporter.py /var/reports/system_health
```

### Example 3: Automated Daily Reports (Windows)

Create a scheduled task using PowerShell:

```powershell
$action = New-ScheduledTaskAction -Execute "python" -Argument "C:\Scripts\system_health_reporter.py C:\Reports"
$trigger = New-ScheduledTaskTrigger -Daily -At 2AM
Register-ScheduledTask -TaskName "SystemHealthReport" -Action $action -Trigger $trigger
```

### Example 4: Integration with Monitoring Systems

```python
import json
from system_health_reporter import SystemCollector

# Collect data programmatically
collector = SystemCollector()
data = collector.collect_all()

# Send to monitoring API
import requests
requests.post('https://monitoring.example.com/api/health', json=data)
```

## 📊 Output Formats

### JSON Output
Complete system data in structured JSON format, perfect for:
- API integrations
- Automated processing
- Data warehousing
- Log aggregation systems

### YAML Output
Human-readable format, ideal for:
- Configuration management
- Documentation
- Version control
- Manual review

### CSV Output
Flattened data structure, perfect for:
- Excel/LibreOffice Calc
- Data analysis
- Spreadsheet pivots
- Database imports

### HTML Dashboard
Interactive web-based report featuring:
- Responsive design
- Collapsible sections
- Color-coded status indicators (green/yellow/red)
- Easy navigation
- Print-friendly layout

## 🎯 What Data is Collected?

### System Metadata
- Hostname and FQDN
- Report timestamp (UTC and local)
- Platform information

### Operating System
- OS name, version, and build
- Kernel version
- Architecture (32/64-bit)
- Distribution info (Linux)

### CPU Information
- Processor brand and model
- Physical and logical cores
- Current frequency and limits
- Real-time usage percentage

### Memory
- Total RAM and available memory
- Used memory and percentage
- Swap space information

### Disk Storage
- All mounted partitions
- Total, used, and free space
- Filesystem types
- Usage percentages
- Block device details (Linux)

### GPU/Graphics
- GPU name and model
- VRAM/memory
- Driver version and date
- Metal support (macOS)
- NVIDIA GPU details (Linux with nvidia-smi)

### Network Interfaces
- Interface names and status
- IP addresses (IPv4/IPv6)
- MAC addresses
- Network speed and MTU
- Bytes sent/received
- Packet statistics

### Processes
- Top 10 processes by CPU usage
- Top 10 processes by memory usage
- Process IDs, names, and owners

### Drivers/Modules
- Windows: PnP Signed Drivers
- macOS: Kernel Extensions (KEXTs)
- Linux: Loaded kernel modules

### Installed Software
- Windows: Registry-based application list
- macOS: Installed applications
- Linux: Package manager inventory (dpkg/rpm)

### Power & Battery
- Battery percentage
- Charging status
- Time remaining estimate
- Power assertions (macOS)

### Sensors
- Temperature sensors
- Fan speeds (when available)
- Voltage readings

## 🛡️ Security & Privacy

### No Admin Required
The tool runs with standard user privileges and gracefully handles permission errors. Administrative access is **not required**, though some advanced features may be unavailable without it.

### Local Processing Only
All data collection and processing happens **locally** on your machine. No data is sent to external servers unless you explicitly integrate it with your own monitoring systems.

### Open Source
The entire codebase is open source and auditable. Review the code to ensure it meets your security requirements.

## 🔧 Advanced Configuration

### Custom Timeout Values

Edit the script to adjust timeout values for slow systems:

```python
# In system_health_reporter.py, modify:
def run_command(cmd: List[str], timeout: int = 30, shell: bool = False):
    # Change timeout to 60 seconds for slow commands
    timeout = 60
```

### Excluding Specific Collectors

Comment out specific collectors if not needed:

```python
def collect_all(self) -> Dict[str, Any]:
    self.collect_metadata()
    self.collect_os_info()
    # self.collect_software()  # Skip software inventory
    # self.collect_drivers()   # Skip driver enumeration
```

### Custom Output Format

Add your own output format by extending the `OutputWriter` class:

```python
def write_xml(self) -> str:
    """Write XML output."""
    filepath = self._get_filename("xml")
    # Your XML generation code here
    return filepath
```

## 🐛 Troubleshooting

### Issue: "Failed to install psutil"

**Solution**: Install manually with pip:
```bash
pip install psutil
# On Windows, also install wmi:
pip install wmi
```

### Issue: "Permission denied" errors

**Solution**: Some data requires elevated privileges. Run with:
```bash
# Linux/macOS
sudo python3 system_health_reporter.py

# Windows (as Administrator)
python system_health_reporter.py
```

### Issue: Slow execution on Linux

**Solution**: The `system_profiler` equivalent commands on Linux can be slow. Consider:
- Using SSD instead of HDD
- Reducing timeout values
- Excluding software inventory for faster runs

### Issue: Missing GPU information

**Solution**:
- **Windows**: Ensure WMI service is running
- **Linux**: Install `lspci` and `nvidia-smi` (for NVIDIA GPUs)
- **macOS**: System Profiler should work by default

### Issue: HTML report doesn't open automatically

**Solution**: Manually open the HTML file:
```bash
# Linux
xdg-open ~/system_health_reports/system_health_*.html

# macOS
open ~/system_health_reports/system_health_*.html

# Windows
start %USERPROFILE%\system_health_reports\system_health_*.html
```

## 📚 API Reference

### SystemCollector Class

Main class for collecting system information.

#### Methods

- `collect_all()` - Run all collectors and return complete data dictionary
- `collect_metadata()` - Collect report metadata
- `collect_os_info()` - Collect OS information
- `collect_cpu_info()` - Collect CPU details
- `collect_memory_info()` - Collect RAM and swap info
- `collect_disk_info()` - Collect disk/partition data
- `collect_gpu_info()` - Collect GPU information
- `collect_network_info()` - Collect network interfaces
- `collect_processes()` - Collect top processes
- `collect_drivers()` - Collect driver information
- `collect_software()` - Collect installed software
- `collect_power_battery()` - Collect battery status
- `collect_sensors()` - Collect temperature sensors

### OutputWriter Class

Handles output file generation in multiple formats.

#### Methods

- `write_all()` - Generate all output formats
- `write_json()` - Generate JSON output
- `write_yaml()` - Generate YAML output
- `write_csv()` - Generate CSV output
- `write_html()` - Generate HTML dashboard

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Commit your changes**: `git commit -m 'Add amazing feature'`
4. **Push to the branch**: `git push origin feature/amazing-feature`
5. **Open a Pull Request**

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/system-health-reporter.git
cd system-health-reporter

# Install dev dependencies
pip install psutil pytest black pylint

# Run tests
pytest tests/

# Format code
black system_health_reporter.py

# Lint
pylint system_health_reporter.py
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**memarzade-dev**

- GitHub: [@memarzade-dev](https://github.com/memarzade-dev)

## 🙏 Acknowledgments

- [psutil](https://github.com/giampaolo/psutil) - Cross-platform system utilities
- [WMI](https://pypi.org/project/WMI/) - Windows Management Instrumentation

## 📞 Support

If you encounter any issues or have questions:

1. **Check the [Troubleshooting](#-troubleshooting) section**
2. **Search [existing issues](https://github.com/memarzade-dev/system-health-reporter/issues)**
3. **Open a [new issue](https://github.com/memarzade-dev/system-health-reporter/issues/new)** with:
   - Your OS and Python version
   - Complete error message
   - Steps to reproduce

## 🗺️ Roadmap

- [ ] Add support for Docker container health
- [ ] Kubernetes node information collector
- [ ] Real-time monitoring dashboard (WebSocket)
- [ ] Historical data tracking and trending
- [ ] Alert thresholds and notifications
- [ ] REST API server mode
- [ ] Prometheus exporter
- [ ] Grafana dashboard templates

## ⭐ Star History

If you find this project useful, please consider giving it a star on GitHub!

---

**Made with ❤️ by memarzade-dev**