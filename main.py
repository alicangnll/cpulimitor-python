#!/usr/bin/env python3
import argparse
import os
import signal
import time
import psutil
import sys

def parse_args():
    parser = argparse.ArgumentParser(description='Python CPU limiter (like cpulimit)')
    parser.add_argument('--pid', type=int, required=True, help='Target process PID')
    parser.add_argument('--limit', type=float, required=True, help='CPU usage limit (e.g., 50.0 = 50%)')
    parser.add_argument('--interval', type=float, default=0.1, help='Sampling interval in seconds (default: 0.1)')
    return parser.parse_args()

def limit_cpu(pid, limit_percent, interval):
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        print(f"[!] Error: No process found with PID {pid}.")
        sys.exit(1)

    num_cpus = psutil.cpu_count()
    max_cpu = 100 * num_cpus

    if limit_percent > max_cpu:
        print(f"[!] Error: Specified limit {limit_percent}% exceeds total system CPU capacity.")
        sys.exit(1)

    print(f"[+] Applying CPU limit of {limit_percent}% to PID {pid} (CPU cores: {num_cpus})")

    last_time = time.time()
    last_cpu = proc.cpu_times().user + proc.cpu_times().system

    while True:
        time.sleep(interval)

        try:
            current_time = time.time()
            current_cpu = proc.cpu_times().user + proc.cpu_times().system
        except psutil.NoSuchProcess:
            print("[*] Process has terminated.")
            break

        elapsed_time = current_time - last_time
        used_cpu = current_cpu - last_cpu
        cpu_percent = (used_cpu / elapsed_time) * 100 if elapsed_time > 0 else 0

        if cpu_percent > limit_percent:
            os.kill(pid, signal.SIGSTOP)
            sleep_time = used_cpu / (limit_percent / 100) - elapsed_time
            sleep_time = max(sleep_time, 0.01)
            time.sleep(sleep_time)
            os.kill(pid, signal.SIGCONT)

        last_time = time.time()
        last_cpu = proc.cpu_times().user + proc.cpu_times().system

def main():
    args = parse_args()
    limit_cpu(args.pid, args.limit, args.interval)

if __name__ == '__main__':
    main()
