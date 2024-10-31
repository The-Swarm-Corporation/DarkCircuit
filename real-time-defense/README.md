# Security System Monitor

A cross-platform security monitoring tool designed to protect systems by monitoring file integrity and process behavior in real-time.

## Features

- **File System Monitoring**
  - Real-time monitoring of critical system directories
  - File integrity verification using SHA-256 hashing
  - Baseline system scanning
  - Detection of unauthorized modifications

- **Process Monitoring**
  - Detection of suspicious process locations
  - Platform-specific process validation
  - Monitoring of unsigned binaries (macOS)
  - Detection of system process masquerading

- **Cross-Platform Support**
  - macOS support with launchd service integration
  - Windows support with system directory monitoring
  - Linux/Unix basic support

## Requirements

- Python 3.7+
- Required Python packages:
  ```
  watchdog
  psutil
  ```

## Installation

1. Clone the repository:
   ```bash
   git clone [repository-url]
   cd security-monitor
   ```

2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Running as a Standalone Monitor

```bash
# On macOS/Linux
sudo python3 defense.py

# On Windows (Run as Administrator)
python defense.py
```

### Installing as a System Service

```bash
# On macOS
sudo python3 defense.py --install
```

## Protected Directories

### macOS
- /System/Library
- /Library
- /usr/bin
- /bin
- /usr/local/bin
- /Applications

### Windows
- C:\Windows\System32
- C:\Program Files
- C:\Program Files (x86)

## Logging

Logs are stored in:
- macOS: `/var/log/security_monitor.log`
- Windows: `C:\ProgramData\SecurityMonitor\security_monitor.log`

## Security Features

1. **File Integrity Monitoring**
   - Creates baseline of critical system files
   - Monitors for unauthorized modifications
   - Excludes temporary and cache files

2. **Process Security**
   - Monitors for processes running from suspicious locations
   - Validates system process signatures
   - Detects unauthorized root/admin processes

3. **Service Integration**
   - Runs as a system service
   - Automatic startup on boot
   - Continuous monitoring

## Development

The tool is structured to be easily extensible. Key components:

- `SecurityMonitor`: Main monitoring class
- `FileSystemEventHandler`: Handles filesystem events
- Platform-specific monitoring functions

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Submit a pull request

## License

[Add your license information here]

## Disclaimer

This tool is designed for defensive security monitoring purposes only. Always:
- Test in an isolated environment first
- Obtain necessary permissions before deployment
- Follow your organization's security policies
- Monitor system performance impact

## Support

For issues and feature requests, please:
1. Check existing issues
2. Create a new issue with detailed information
3. Include system information and logs

## Authors

[Add author information here]

## Acknowledgments

- Watchdog library contributors
- Python psutil team
- Security research community