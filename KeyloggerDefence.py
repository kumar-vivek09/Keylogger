#!/usr/bin/env python3
import psutil
import os
import time
import threading
import signal
import sys
from pathlib import Path
import subprocess
import platform

class KeyloggerDefense:
    def init(self):
        self.monitoring = False
        self.log_file = "keylog.txt"
        self.alert_count = 0
        self.blocked_processes = []

    def detect_pynput_processes(self):
        """Detect processes using pynput library"""
        suspicious_processes = []

        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                # Check if process is Python and uses pynput
                if proc.info['name'] and 'python' in proc.info['name'].lower():
                    cmdline = proc.info['cmdline']
                    if cmdline:
                        cmdline_str = ' '.join(cmdline)
                        if 'pynput' in cmdline_str or 'keylogger' in cmdline_str.lower():
                            suspicious_processes.append({
                                'pid': proc.info['pid'],
                                'name': proc.info['name'],
                                'cmdline': cmdline_str
                            })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        return suspicious_processes

    def detect_keylog_file_activity(self):
        """Monitor for keylog file creation and modification"""
        if os.path.exists(self.log_file):
            try:
                stat_info = os.stat(self.log_file)
                return {
                    'file_exists': True,
                    'size': stat_info.st_size,
                    'modified': time.ctime(stat_info.st_mtime),
                    'path': os.path.abspath(self.log_file)
                }
            except Exception as e:
                return {'error': str(e)}
        return {'file_exists': False}

    def block_keylogger_process(self, pid):
        """Terminate the keylogger process"""
        try:
            process = psutil.Process(pid)
            process.terminate()
            time.sleep(1)  # Give it time to terminate gracefully

            if process.is_running():
                process.kill()  # Force kill if still running

            self.blocked_processes.append(pid)
            return True
        except psutil.NoSuchProcess:
            return True  # Process already terminated
        except psutil.AccessDenied:
            return False
        except Exception as e:
            print(f"Error blocking process {pid}: {e}")
            return False

    def secure_keylog_file(self):
        """Remove or secure the keylog file"""
        actions_taken = []

        if os.path.exists(self.log_file):
            try:
                # First, try to remove the file
                os.remove(self.log_file)
                actions_taken.append("Removed keylog file")
            except PermissionError:
                try:
                    # If can't remove, try to clear its contents
                    with open(self.log_file, 'w') as f:
                        f.write("")
                    actions_taken.append("Cleared keylog file contents")
                except Exception as e:
                    actions_taken.append(f"Failed to secure file: {e}")
            except Exception as e:
                actions_taken.append(f"Error handling file: {e}")

        return actions_taken

    def monitor_vs_code_processes(self):
        """Monitor VS Code for Python processes that might be keyloggers"""
        vscode_processes = []

        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'ppid']):
            try:
                if proc.info['name'] and 'code' in proc.info['name'].lower():
                    # Look for child Python processes
                    children = proc.children(recursive=True)
                    for child in children:
                        if 'python' in child.name().lower():
                            cmdline = ' '.join(child.cmdline())
                            if any(keyword in cmdline.lower() for keyword in ['pynput', 'listener', 'keylog']):
                                vscode_processes.append({
                                    'pid': child.pid,
                                    'name': child.name(),
                                    'cmdline': cmdline,
                                    'parent': proc.info['name']
                                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        return vscode_processes

    def run_defense(self):
        """Main defense loop"""
        print("🛡  Keylogger Defense System Started")
        print("=" * 50)

        self.monitoring = True

        while self.monitoring:
            try:
                # 1. Detect pynput processes
                suspicious_procs = self.detect_pynput_processes()

                # 2. Check VS Code processes
                vscode_procs = self.monitor_vs_code_processes()

                # 3. Monitor keylog file
                file_status = self.detect_keylog_file_activity()

                # 4. Take defensive action if threats detected
                if suspicious_procs or vscode_procs or file_status.get('file_exists'):
                    self.alert_count += 1
                    print(f"\n⚠  THREAT DETECTED (Alert #{self.alert_count})")
                    print("-" * 30)

                    if suspicious_procs:
                        print("🔍 Suspicious pynput processes found:")
                        for proc in suspicious_procs:
                            print(f"   PID: {proc['pid']} - {proc['name']}")
                            print(f"   Command: {proc['cmdline'][:80]}...")

                            # Block the process
                            if self.block_keylogger_process(proc['pid']):
                                print(f"   ✅ Process {proc['pid']} terminated")
                            else:
                                print(f"   ❌ Failed to terminate process {proc['pid']}")

                    if vscode_procs:
                        print("🔍 VS Code keylogger processes found:")
                        for proc in vscode_procs:
                            print(f"   PID: {proc['pid']} - {proc['name']}")
                            print(f"   Parent: {proc['parent']}")

                            if self.block_keylogger_process(proc['pid']):
                                print(f"   ✅ VS Code process {proc['pid']} terminated")
                            else:
                                print(f"   ❌ Failed to terminate VS Code process {proc['pid']}")

                    if file_status.get('file_exists'):
                        print(f"🔍 Keylog file detected: {file_status.get('path')}")
                        print(f"   Size: {file_status.get('size')} bytes")
                        print(f"   Last modified: {file_status.get('modified')}")

                        actions = self.secure_keylog_file()
                        for action in actions:
                            print(f"   🛡 {action}")

                    print(f"🔐 Defense actions completed at {time.strftime('%H:%M:%S')}")

                else:
                    # Clear screen periodically and show status
                    if self.alert_count == 0 and int(time.time()) % 10 == 0:
                        print(f"✅ System secure - Monitoring... {time.strftime('%H:%M:%S')}")

                time.sleep(2)  # Check every 2 seconds

            except KeyboardInterrupt:
                print("\n🛑 Defense system stopped by user")
                self.monitoring = False
                break
            except Exception as e:
                print(f"❌ Error in defense loop: {e}")
                time.sleep(5)

    def stop_defense(self):
        """Stop the monitoring"""
        self.monitoring = False
        print("🛡 Defense system stopped")

def main():
    """Main function to run the defense system"""
    print("Keylogger Defense System")
    print("========================")
    print("This tool will monitor and block pynput-based keyloggers.")
    print("Press Ctrl+C to stop monitoring.\n")

    defense = KeyloggerDefense()

    try:
        defense.run_defense()
    except KeyboardInterrupt:
        defense.stop_defense()
        print("\nDefense system shut down safely.")

if name == "main":
    main()
