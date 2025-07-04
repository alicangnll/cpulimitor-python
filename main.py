#!/usr/bin/env python3
import argparse
import os
import signal
import time
import psutil
import sys
import logging

# Global dictionary to keep track of processes that were suspended by this script.
_suspended_processes = {}

# Global flag to indicate if the currently limited process is suspended by *this* script.
_is_currently_suspended_by_script = False

# Global variable to store parsed arguments, accessible by signal handler
_parsed_args = None

# Global logger instance
logger = logging.getLogger(__name__)

def parse_args():
    parser = argparse.ArgumentParser(description='Python CPU limiter (like cpulimit)')
    parser.add_argument('--pid', type=int, required=True, help='Target process PID')
    parser.add_argument('--limit', type=float, required=True, help='CPU usage limit (e.g., 50.0 = 50%)')
    parser.add_argument('--interval', type=float, default=0.1, help='Sampling interval in seconds (default: 0.1)')
    parser.add_argument('--no-resume-on-exit', action='store_true', default=False,
                        help='Do NOT automatically resume the process if the script exits. '
                             'The process might remain suspended (SIGSTOP-ed) if active upon exit.')
    # New argument for logging to a file
    parser.add_argument('--log-file', type=str, default=None,
                        help='Path to a file to log output. If not specified, output will be suppressed.')
    return parser.parse_args()

def configure_logging(log_file_path):
    # Clear any existing handlers to prevent duplicate output if called multiple times
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    # By default, set the level to CRITICAL to suppress all output unless a handler is explicitly added.
    logger.setLevel(logging.CRITICAL)

    if log_file_path:
        # Log to file if --log-file is specified
        try:
            # Ensure the directory exists
            log_dir = os.path.dirname(log_file_path)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True) # Create directory if it doesn't exist

            file_handler = logging.FileHandler(log_file_path)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            # If logging to a file is enabled, set the logger level to INFO.
            logger.setLevel(logging.INFO)
        except Exception as e:
            # Fallback for logging setup issues: print to console for this specific error, then ensure no handlers are active
            # This is the only place where a direct print might be acceptable if logging setup itself fails.
            print(f"Error setting up file logging to {log_file_path}: {e}. Output will be suppressed.")
            logger.handlers.clear() # Ensure no handlers are left if file setup failed.
            logger.setLevel(logging.CRITICAL) # Re-assert critical level to suppress future messages.


def graceful_exit_handler(signum, frame):
    """
    Handles script termination (e.g., Ctrl+C) by optionally resuming any processes
    that were actively suspended by this script.
    """
    logger.info("[*] Ctrl+C detected. Attempting to manage suspended processes before exiting...")
    global _is_currently_suspended_by_script # Access the global flag
    global _parsed_args # Access the global arguments

    # Check the --no-resume-on-exit option
    if _parsed_args and _parsed_args.no_resume_on_exit:
        logger.info("[!] --no-resume-on-exit flag is active. Process will NOT be automatically resumed.")
        # We still need to clean up the _suspended_processes list
        for pid, proc in list(_suspended_processes.items()):
            if pid in _suspended_processes:
                del _suspended_processes[pid]
        sys.exit(0) # Exit the script

    # If --no-resume-on-exit is NOT active, proceed with resuming
    for pid, proc in list(_suspended_processes.items()):
        if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
            try:
                if proc.status() == psutil.STATUS_STOPPED:
                    logger.info(f"[*] Resuming PID {pid}...")
                    os.kill(pid, signal.SIGCONT)
                    # Reset the flag if this was the process currently being handled
                    # This assumes single PID operation, if multiple PIDs were supported, this logic would need to change.
                    if pid == list(_suspended_processes.keys())[0]:
                        _is_currently_suspended_by_script = False
                else:
                    logger.info(f"[*] PID {pid} is already running. No action needed.")
            except psutil.NoSuchProcess:
                logger.info(f"[*] PID {pid} already terminated.")
            except psutil.AccessDenied:
                logger.error(f"[*] Access denied when trying to resume PID {pid}. Please ensure script is run with sufficient permissions (e.g., sudo).")
            except Exception as e:
                logger.error(f"[*] Error resuming PID {pid}: {e}")
        else:
            logger.info(f"[*] PID {pid} is not running or is a zombie. No action needed.")

        # Clean up from the global tracking list as we are exiting.
        if pid in _suspended_processes:
            del _suspended_processes[pid]

    sys.exit(0) # Exit the script gracefully

def limit_cpu(pid, limit_percent, interval):
    global _is_currently_suspended_by_script
    global _parsed_args # Access the global arguments for no_resume_on_exit check

    try:
        proc = psutil.Process(pid)
        _suspended_processes[pid] = proc # Add to global tracking
    except psutil.NoSuchProcess:
        logger.error(f"[!] Error: No process found with PID {pid}.")
        if pid in _suspended_processes:
            del _suspended_processes[pid]
        return

    num_cpus = psutil.cpu_count(logical=True)

    if limit_percent <= 0:
        logger.error("[!] Error: CPU limit must be greater than 0%.")
        if pid in _suspended_processes:
            del _suspended_processes[pid]
        return
    if limit_percent > 100.0 * num_cpus:
        logger.error(f"[!] Error: Specified limit {limit_percent}% exceeds total system CPU capacity ({100 * num_cpus}%).")
        if pid in _suspended_processes:
            del _suspended_processes[pid]
        return

    logger.info(f"[+] Applying CPU limit of {limit_percent}% to PID {pid} (CPU cores: {num_cpus})")

    last_time = time.time()
    try:
        last_cpu = proc.cpu_times().user + proc.cpu_times().system
    except psutil.NoSuchProcess:
        logger.error(f"[!] Error: Process {pid} disappeared before initial CPU time read.")
        if pid in _suspended_processes:
            del _suspended_processes[pid]
        return

    while True:
        try:
            if not proc.is_running() or proc.status() == psutil.STATUS_ZOMBIE:
                logger.info("[*] Process has terminated.")
                break

            time.sleep(interval)

            current_time = time.time()
            current_cpu_times = proc.cpu_times()
            current_cpu = current_cpu_times.user + current_cpu_times.system

            elapsed_time = current_time - last_time
            used_cpu = current_cpu - last_cpu
            cpu_percent = (used_cpu / elapsed_time) * 100 if elapsed_time > 0 else 0

            if cpu_percent > limit_percent:
                logger.info(f"[>] PID {pid} usage {cpu_percent:.2f}% > Limit {limit_percent}%. Suspending...")
                os.kill(pid, signal.SIGSTOP)
                _is_currently_suspended_by_script = True

                sleep_time = interval * (cpu_percent - limit_percent) / limit_percent
                sleep_time = max(sleep_time, 0.001)

                logger.info(f"[<] Suspending for {sleep_time:.4f} seconds...")
                time.sleep(sleep_time)

                if proc.is_running() and proc.status() == psutil.STATUS_STOPPED:
                    logger.info(f"[>] Resuming PID {pid}...")
                    os.kill(pid, signal.SIGCONT)
                    _is_currently_suspended_by_script = False
                elif not proc.is_running():
                    logger.info(f"[*] Process {pid} terminated while suspended.")
                    break

            last_time = current_time
            last_cpu = current_cpu

        except psutil.NoSuchProcess:
            logger.info("[*] Process terminated during operation.")
            break
        except psutil.AccessDenied:
            logger.error(f"[!] Access denied to process {pid}. Please run with sufficient permissions (e.g., sudo).")
            break
        except Exception as e:
            logger.error(f"[!] An unexpected error occurred: {e}")
            break

    # --- Cleanup after the while loop finishes naturally (not via Ctrl+C) ---
    # Only resume if --no-resume-on-exit is NOT active and the process was suspended by us.
    if _is_currently_suspended_by_script and pid in _suspended_processes and not _parsed_args.no_resume_on_exit:
        if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
            try:
                if proc.status() == psutil.STATUS_STOPPED:
                    logger.info(f"[+] Ensuring PID {pid} is resumed before script exit...")
                    os.kill(pid, signal.SIGCONT)
            except psutil.NoSuchProcess:
                pass
            except psutil.AccessDenied:
                logger.error(f"[!] Cannot resume PID {pid} on final exit due to Access Denied.")
            except Exception as e:
                logger.error(f"[!] Error on final resume of PID {pid}: {e}")
        _is_currently_suspended_by_script = False

    # Remove the process from global tracking after `limit_cpu` is done with it.
    if pid in _suspended_processes:
        del _suspended_processes[pid]


def main():
    global _parsed_args # Make args accessible globally for the signal handler
    _parsed_args = parse_args()

    # Configure logging based on the --log-file argument
    configure_logging(_parsed_args.log_file)

    # Set up the signal handler for Ctrl+C (SIGINT)
    signal.signal(signal.SIGINT, graceful_exit_handler)

    if _parsed_args.pid:
        limit_cpu(_parsed_args.pid, _parsed_args.limit, _parsed_args.interval)
    else:
        # This part should ideally not be reached due to argparse 'required=True'
        logger.error("[!] No PID specified. Use --pid to specify a process to limit.")
        sys.exit(1)


if __name__ == '__main__':
    main()