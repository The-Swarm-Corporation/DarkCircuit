import os
import sys
import time
import hashlib
import logging
import platform
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil
from typing import List, Dict, Set


class SecurityMonitorDaemon:
    def __init__(self):
        self.stdin_path = "/dev/null"
        self.stdout_path = "/dev/null"
        self.stderr_path = "/dev/null"
        self.pidfile_path = "/var/run/securitymonitor.pid"
        self.pidfile_timeout = 5


class SecurityMonitor(FileSystemEventHandler):
    def __init__(self):
        self.system = platform.system()
        self.protected_paths = self.get_protected_paths()
        self.log_file = self.get_log_path()
        self.known_good_hashes: Dict[str, str] = {}
        self.excluded_extensions: Set[str] = {'.tmp', '.log', '.cache'}
        self.setup_logging()
        self.baseline_system()

    def get_protected_paths(self) -> List[str]:
        """Get system-specific protected paths"""
        if self.system == "Darwin":  # macOS
            return [
                "/System/Library",
                "/Library",
                "/usr/bin",
                "/bin",
                "/usr/local/bin",
                "/Applications",
            ]
        elif self.system == "Windows":
            return [
                "C:\\Windows\\System32",
                "C:\\Program Files",
                "C:\\Program Files (x86)",
            ]
        else:  # Linux/Unix
            return ["/bin", "/usr/bin", "/usr/local/bin", "/etc"]

    def get_log_path(self) -> str:
        """Get system-specific log path"""
        if self.system == "Darwin":
            return "/var/log/security_monitor.log"
        elif self.system == "Windows":
            return "C:\\ProgramData\\SecurityMonitor\\security_monitor.log"
        else:
            return "/var/log/security_monitor.log"

    def setup_logging(self):
        """Configure logging with rotation"""
        log_dir = os.path.dirname(self.log_file)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
        )

    def get_file_hash(self, filepath: str) -> str:
        """Calculate SHA-256 hash of a file with improved error handling"""
        try:
            if os.path.isfile(filepath):
                with open(filepath, "rb") as f:
                    return hashlib.sha256(f.read()).hexdigest()
        except (IOError, PermissionError) as e:
            logging.debug(f"Unable to hash {filepath}: {str(e)}")
        return None

    def get_file_signature(self, filepath: str) -> str:
        """Get code signature information for macOS/Windows"""
        try:
            if self.system == "Darwin":
                cmd = ["codesign", "-dv", filepath]
                result = subprocess.run(
                    cmd, capture_output=True, text=True
                )
                return result.stdout
            elif self.system == "Windows":
                cmd = ["sigcheck.exe", "-nobanner", filepath]
                result = subprocess.run(
                    cmd, capture_output=True, text=True
                )
                return result.stdout
        except subprocess.SubprocessError:
            return None
        
        
    def baseline_system(self):
        """Create baseline of known good files"""
        try:
            print("Creating system baseline... This may take a few minutes.")
            logging.info("Starting system baseline creation")
            
            for base_path in self.protected_paths:
                if not os.path.exists(base_path):
                    logging.warning(f"Protected path does not exist: {base_path}")
                    continue
                    
                print(f"Scanning: {base_path}")
                for root, _, files in os.walk(base_path):
                    for file in files:
                        try:
                            filepath = os.path.join(root, file)
                            
                            # Skip files with excluded extensions
                            if any(filepath.endswith(ext) for ext in self.excluded_extensions):
                                continue
                                
                            # Skip system links
                            if os.path.islink(filepath):
                                continue
                                
                            file_hash = self.get_file_hash(filepath)
                            if file_hash:
                                self.known_good_hashes[filepath] = file_hash
                                
                        except (PermissionError, OSError) as e:
                            logging.debug(f"Unable to baseline file {filepath}: {str(e)}")
                            continue
                            
            logging.info(f"Baseline complete. Monitoring {len(self.known_good_hashes)} files")
            print(f"Baseline complete. Monitoring {len(self.known_good_hashes)} files")
            
        except Exception as e:
            logging.error(f"Error during system baseline: {str(e)}")
            print(f"Error during system baseline: {str(e)}")
            sys.exit(1)


    def check_process_integrity(self):
        """Platform-specific process monitoring"""
        suspicious_locations = self.get_suspicious_locations()

        for proc in psutil.process_iter(
            ["pid", "name", "exe", "cmdline"]
        ):
            try:
                proc_info = proc.info

                # Check process executable location
                if proc_info["exe"]:
                    exe_path = proc_info["exe"].lower()
                    if any(
                        loc in exe_path
                        for loc in suspicious_locations
                    ):
                        self.handle_suspicious_process(proc_info)

                # Check for hidden processes (platform specific)
                if self.system == "Darwin":
                    self.check_macos_process(proc)
                elif self.system == "Windows":
                    self.check_windows_process(proc)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def get_suspicious_locations(self) -> List[str]:
        """Get platform-specific suspicious locations"""
        if self.system == "Darwin":
            return [
                "/private/tmp",
                "/Users/Shared",
                "/Library/Application Support/tmp",
            ]
        elif self.system == "Windows":
            return [
                "temp",
                "tmp",
                "%temp%",
                "appdata\\local\\temp",
                "windows\\temp",
            ]
        else:
            return ["/tmp", "/var/tmp", "/dev/shm"]

    def check_macos_process(self, proc):
        """macOS-specific process checks"""
        try:
            # Check for unsigned binaries
            if proc.exe():
                signature = self.get_file_signature(proc.exe())
                if not signature or "valid on disk" not in signature:
                    logging.warning(
                        f"Unsigned binary detected: {proc.exe()}"
                    )

            # Check for processes masquerading as system processes
            if (
                proc.username() == "root"
                and proc.name()
                not in self.get_legitimate_system_processes()
            ):
                logging.warning(
                    f"Suspicious root process detected: {proc.name()}"
                )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def check_windows_process(self, proc):
        """Windows-specific process checks"""
        try:
            # Check for processes without a valid parent
            if proc.ppid() == 0 and proc.name() not in [
                "System",
                "Registry",
            ]:
                logging.warning(
                    f"Process with no parent detected: {proc.name()}"
                )

            # Check for processes masquerading as system processes
            if (
                proc.exe()
                and "windows\\system32" in proc.exe().lower()
            ):
                signature = self.get_file_signature(proc.exe())
                if (
                    not signature
                    or "Microsoft Windows" not in signature
                ):
                    logging.warning(
                        f"Suspicious system process detected: {proc.exe()}"
                    )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def get_legitimate_system_processes(self) -> List[str]:
        """Get list of legitimate system processes"""
        if self.system == "Darwin":
            return [
                "launchd",
                "kernel_task",
                "systemstats",
                "configd",
            ]
        elif self.system == "Windows":
            return [
                "System",
                "Registry",
                "smss.exe",
                "csrss.exe",
                "wininit.exe",
            ]
        return []

    def run_as_service(self):
        """Run the monitor as a background service"""
        if self.system == "Darwin":
            self.run_as_macos_service()
        elif self.system == "Windows":
            self.run_as_windows_service()
        else:
            self.run_as_linux_service()

    def run_as_macos_service(self):
        """Set up macOS launchd service"""
        plist_path = (
            "/Library/LaunchDaemons/com.security.monitor.plist"
        )
        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.security.monitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{os.path.abspath(__file__)}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{self.log_file}</string>
    <key>StandardErrorPath</key>
    <string>{self.log_file}</string>
</dict>
</plist>"""

        with open(plist_path, "w") as f:
            f.write(plist_content)

        # Load the service
        subprocess.run(["launchctl", "load", plist_path])


def main():
    monitor = SecurityMonitor()

    # Set up filesystem observer
    observer = Observer()
    for path in monitor.protected_paths:
        observer.schedule(monitor, path, recursive=True)
    observer.start()

    try:
        while True:
            monitor.check_process_integrity()
            time.sleep(10)
    except KeyboardInterrupt:
        observer.stop()
        observer.join()


if __name__ == "__main__":
    # Check if running with appropriate privileges
    if os.geteuid() != 0:
        print(
            "This program must be run with administrator privileges"
        )
        sys.exit(1)

    monitor = SecurityMonitor()
    monitor.run_as_service()
