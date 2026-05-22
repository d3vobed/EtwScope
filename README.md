# ETWScope

`ETWScope` is a professional, hybrid Rust/Python Windows telemetry research platform designed for exploring Event Tracing for Windows (ETW) provider activity in real time.

## Purpose & Ethical Statement
**This project is purely defensive and research-oriented.** It is NOT an offensive security tool or an EDR bypass framework. It is intended for detection engineering, telemetry resilience scoring (TRS), and behavioral anomaly detection.

## Architecture
The platform is built on a high-performance hybrid stack:
- **Backend (Rust):** Provides a blazing-fast ETW subscription engine capable of parsing thousands of ETW events per second natively on Windows. On Linux development environments, it supports file-based streaming (`--mock`) to emulate live ingestion.
- **Frontend & Analysis (Python):** Uses `Textual` for a rich Terminal User Interface (TUI). It consumes the JSON stream from the backend and calculates sliding-window entropy, timing variance ($CV_t$), and TRS.
- **Rules Engine:** A Sigma/YARA-inspired YAML detection engine for stateful sequence tracking.

## Installation

### Prerequisites
- Rust (Cargo)
- Python 3.11+

### Setup
1. **Compile Backend**
   ```bash
   cd backend
   cargo build --release
   cd ..
   ```

2. **Install Python Dependencies**
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

## Usage

### Testing on Linux (Mock Stream)
If you are developing on Linux or macOS, you can simulate a live ETW session using the included samples:
```bash
python main.py --mock samples/mutated_kp.json
```

### Future Windows Deployment
To run on a live Windows machine, compile the backend targeting Windows (`cargo build --target x86_64-pc-windows-msvc`) and remove the `--mock` flag from the invocation.

## Roadmap
- Machine Learning Anomaly Detection
- Graph database backend for visualization
- Full native Sigma rule conversion
- Distributed telemetry collection agents
