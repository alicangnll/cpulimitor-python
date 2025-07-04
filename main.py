#!/usr/bin/env python3
import argparse
import os
import signal
import time
import psutil
import sys

# Global dictionary to keep track of processes that were suspended by this script.
# This is crucial for the graceful exit handler.
_suspended_processes = {}

# Global flag to indicate if the currently limited process is suspended by *this* script.
# This helps avoid trying to resume a process that's already running or terminated.
_is_currently_suspended_by_script = False

def parse_args():
    parser = argparse.ArgumentParser(description='Python CPU limiter (like cpulimit)')
    parser.add_argument('--pid', type=int, required=True, help='Target process PID')
    parser.add_argument('--limit', type=float, required=True, help='CPU usage limit (e.g., 50.0 = 50%)')
    parser.add_argument('--interval', type=float, default=0.1, help='Sampling interval in seconds (default: 0.1)')
    return parser.parse_args()

def graceful_exit_handler(signum, frame):
    """
    Handles script termination (e.g., Ctrl+C) by resuming any processes
    that were actively suspended by this script.
    """
    print("\n[*] Ctrl+C detected. Attempting to resume suspended processes before exiting...")
    global _is_currently_suspended_by_script # Access the global flag

    # Iterate over a copy of the dictionary in case it changes during iteration (e.g., if a process dies)
    for pid, proc in list(_suspended_processes.items()):
        if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
            try:
                # Only attempt to resume if the process is actually in a stopped state.
                if proc.status() == psutil.STATUS_STOPPED:
                    print(f"[*] Resuming PID {pid}...")
                    os.kill(pid, signal.SIGCONT)
                    # Reset the flag if this was the process currently being handled
                    if pid == list(_suspended_processes.keys())[0]: # Assumes single PID operation
                        _is_currently_suspended_by_script = False
                else:
                    print(f"[*] PID {pid} is already running. No action needed.")
            except psutil.NoSuchProcess:
                print(f"[*] PID {pid} already terminated.")
            except psutil.AccessDenied:
                print(f"[*] Access denied when trying to resume PID {pid}. Please ensure script is run with sufficient permissions (e.g., sudo).")
            except Exception as e:
                print(f"[*] Error resuming PID {pid}: {e}")
        else:
            print(f"[*] PID {pid} is not running or is a zombie. No action needed.")

        # Clean up from the global tracking list as we are exiting.
        if pid in _suspended_processes:
            del _suspended_processes[pid]

    sys.exit(0) # Exit the script gracefully

def limit_cpu(pid, limit_percent, interval):
    global _is_currently_suspended_by_script

    try:
        proc = psutil.Process(pid)
        # Add the process to our global tracking list
        _suspended_processes[pid] = proc
    except psutil.NoSuchProcess:
        print(f"[!] Error: No process found with PID {pid}.")
        # If process not found, remove from tracking if it somehow got there
        if pid in _suspended_processes:
            del _suspended_processes[pid]
        return # Exit the function, main will handle the overall script exit

    num_cpus = psutil.cpu_count(logical=True) # Use logical=True for number of logical cores/threads

    if limit_percent <= 0:
        print("[!] Error: CPU limit must be greater than 0%.")
        if pid in _suspended_processes:
            del _suspended_processes[pid]
        return
    if limit_percent > 100.0 * num_cpus:
        print(f"[!] Error: Specified limit {limit_percent}% exceeds total system CPU capacity ({100 * num_cpus}%).")
        if pid in _suspended_processes:
            del _suspended_processes[pid]
        return

    print(f"[+] Applying CPU limit of {limit_percent}% to PID {pid} (CPU cores: {num_cpus})")

    last_time = time.time()
    try:
        last_cpu = proc.cpu_times().user + proc.cpu_times().system
    except psutil.NoSuchProcess:
        print(f"[!] Error: Process {pid} disappeared before initial CPU time read.")
        if pid in _suspended_processes:
            del _suspended_processes[pid]
        return # Exit the function

    while True:
        try:
            # Check if the process is still running or if it has become a zombie
            if not proc.is_running() or proc.status() == psutil.STATUS_ZOMBIE:
                print("[*] Process has terminated.")
                break # Exit the main loop

            time.sleep(interval) # Wait for the next sampling interval

            current_time = time.time()
            current_cpu_times = proc.cpu_times()
            current_cpu = current_cpu_times.user + current_cpu_times.system

            elapsed_time = current_time - last_time
            used_cpu = current_cpu - last_cpu
            # Calculate CPU percentage: (CPU time used / real time elapsed) * 100
            cpu_percent = (used_cpu / elapsed_time) * 100 if elapsed_time > 0 else 0

            # Compare actual CPU usage with the limit
            if cpu_percent > limit_percent:
                print(f"[>] PID {pid} usage {cpu_percent:.2f}% > Limit {limit_percent}%. Suspending...")
                os.kill(pid, signal.SIGSTOP) # Send SIGSTOP to pause the process
                _is_currently_suspended_by_script = True # Mark as suspended by us

                # Calculate how long to keep the process suspended to meet the average limit
                sleep_time = interval * (cpu_percent - limit_percent) / limit_percent
                sleep_time = max(sleep_time, 0.001) # Ensure a minimum sleep to avoid rapid resume/suspend cycles

                print(f"[<] Suspending for {sleep_time:.4f} seconds...")
                time.sleep(sleep_time) # Pause this script's execution

                # After sleeping, check if the process is still running and stopped before resuming it
                if proc.is_running() and proc.status() == psutil.STATUS_STOPPED:
                    print(f"[>] Resuming PID {pid}...")
                    os.kill(pid, signal.SIGCONT) # Send SIGCONT to resume the process
                    _is_currently_suspended_by_script = False # Mark as resumed by us
                elif not proc.is_running():
                    print(f"[*] Process {pid} terminated while suspended.")
                    break # Exit loop if process died while suspended
                # If proc.status() is not STOPPED but is_running(), it might have been resumed externally.
                # In that case, we just continue the loop.

            # Update for the next iteration
            last_time = current_time
            last_cpu = current_cpu

        except psutil.NoSuchProcess:
            print("[*] Process terminated during operation.")
            break # Exit loop if the target process disappears
        except psutil.AccessDenied:
            print(f"[!] Access denied to process {pid}. Please run with sufficient permissions (e.g., sudo).")
            break # Exit loop if we lose permissions
        except Exception as e:
            print(f"[!] An unexpected error occurred: {e}")
            break # Exit loop for any other unexpected error

    # --- Cleanup after the while loop finishes naturally (not via Ctrl+C) ---
    # Ensure the process is resumed if it was left suspended when the loop broke.
    if _is_currently_suspended_by_script and pid in _suspended_processes:
        if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
            try:
                if proc.status() == psutil.STATUS_STOPPED:
                    print(f"[+] Ensuring PID {pid} is resumed before script exit...")
                    os.kill(pid, signal.SIGCONT)
            except psutil.NoSuchProcess:
                pass # Process already gone
            except psutil.AccessDenied:
                print(f"[!] Cannot resume PID {pid} on final exit due to Access Denied.")
            except Exception as e:
                print(f"[!] Error on final resume of PID {pid}: {e}")
        _is_currently_suspended_by_script = False # Reset flag

    # Remove the process from global tracking after `limit_cpu` is done with it.
    if pid in _suspended_processes:
        del _suspended_processes[pid]


def main():
    # Set up the signal handler for Ctrl+C (SIGINT)
    signal.signal(signal.SIGINT, graceful_exit_handler)

    args = parse_args()

    # Your main.py only handles --pid based on the provided content.
    # If you later add --exe or --command, they would go here.
    if args.pid:
        limit_cpu(args.pid, args.limit, args.interval)
    else:
        # This part should ideally not be reached if --pid is set as required in argparse.
        print("[!] No PID specified. Use --pid to specify a process to limit.")
        sys.exit(1) # Exit if no PID is provided (should be caught by argparse)


if __name__ == '__main__':
    main()