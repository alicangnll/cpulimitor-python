# 🚀 CPU Usage Limitor - No More High Resource Utilization!

![Python Logo](https://img.shields.io/badge/python-3.x-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## 📖 About
`cpulimitor-python` is a simple Python script designed to limit the CPU usage of a running process on Linux/macOS systems to a specified percentage. It offers a convenient way to throttle CPU consumption for various applications, leveraging Python's ease of use and cross-platform capabilities via the `psutil` library.

The application works on the principle of briefly pausing (`SIGSTOP`) ⏸️ and resuming (`SIGCONT`) ▶️ the target process at short intervals. This controls the total time the process spends on the CPU, thereby effectively limiting its CPU usage.

## ✨ Features
* Limit the CPU usage of a specific process by its PID. 🎯
* Adjustable CPU limit percentage. 📈
* Configurable control interval (the duration after which the process is checked and a pause/resume decision is made). ⏱️
* User-friendly command-line interface. 💻

## 🧠 How It Works
`cpulimitor-python` uses the `psutil` library to monitor the current CPU usage of the target process. If the process's CPU usage exceeds the specified `limit` percentage within the given `interval` period, the process is temporarily suspended using a `SIGSTOP` signal. Subsequently, the process is resumed with a `SIGCONT` signal. This cycle continuously repeats to ensure the process's average CPU usage stays within the defined limit.

While this method is not a true kernel-level limiter, it provides effective CPU throttling for most scenarios.

## 🛠️ Installation
1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/alicangnll/cpulimit-python.git
    cd cpulimit-python
    ```

2.  **Install Required Libraries:**
    This project uses the `psutil` library. You can install it via pip:
    ```bash
    pip install psutil
    ```

## 🚀 Usage
The script allows you to limit a process by specifying its PID. Typically, running it with `sudo` is necessary due to the need for permissions to suspend and resume processes.

```bash
python3 cpulimit.py --pid <PID> --limit <CPU_LIMIT_PERCENTAGE> [--interval <INTERVAL_SECONDS>]
