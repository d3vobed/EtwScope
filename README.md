# ETWScope

`ETWScope` is a professional, active telemetry ignorance measurement framework designed for exploring Event Tracing for Windows (ETW) provider filtering limits in real time.

## Purpose & Ethical Statement
**This project is purely defensive and research-oriented.** It is NOT an offensive security tool or an EDR bypass framework. It is designed to formally calculate **Telemetry Ignorance**—measuring exactly what percentage of a malware's execution path is ignored or deemed a false positive by standard ETW filtering configurations.

## Architecture
The platform is built as a pure, highly technical terminal measurement instrument:
- **Unified Capture Engine:** Strips away visual "slop" to provide a fast-scrolling Wireshark-style event grid.
- **Mathematical Measurement Console:** Real-time log that calculates Telemetry Ignorance, Event Volume ($F$), and Entropy ($H$) while you dynamically inject payloads.
- **Payload Integration:** Supports triggering up to 4 intensities of code mutation (from standard APIs to HWBP unhooking) directly from the terminal to observe the exact moment the sensors go blind.

## Installation

### Prerequisites
- Python 3.11+
- SilkETW (must be downloaded and accessible)
- (Optional) Visual Studio / GCC to compile the test payload

### Setup
1. **Clone the Repository**
   ```powershell
   git clone git@github.com:d3vobed/EtwScope.git
   cd EtwScope
   ```

2. **Install Python Dependencies**
   ```powershell
   python -m venv venv
   .\venv\Scripts\activate  # On Linux: source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Compile the Baseline Payload (Windows)**
   ```powershell
   cl.exe poc_injector.c
   ```
   *This creates `poc_injector.exe`, a standard CreateRemoteThread injection payload.*

## Usage

ETWScope uses a single, powerful unified command: `capture`.

```powershell
python main.py capture --silketw "C:\Path\To\SilkETW.exe" --provider Microsoft-Windows-Kernel-Process --filter-pid <OPTIONAL_PID> --payload-i1 poc_injector.exe --payload-i2 mutated_direct.exe --payload-i3 mutated_indirect.exe --payload-i4 hwbp.exe
```

### Live Measurement Workflow:
1. **Phase 1: Learning.** When the tool starts, it passively listens to the ETW stream. Let it run for ~10 seconds to learn the background noise of the operating system.
2. **Phase 2: Lock & Monitor.** Press `SPACEBAR`. The tool locks the baseline and begins actively searching for Ignored Telemetry Deviations.
3. **Phase 3: Active Injection.** 
   - Press `1` to inject the baseline payload (`poc_injector.exe`). The measurement console will show standard visibility.
   - Press `2`, `3`, or `4` to inject your advanced STCMF payloads. Watch the Telemetry Ignorance score spike as the payloads bypass the ETW filters.

## Academic Context
This framework acts as the empirical measurement engine for the Secure Telemetry-Driven Code Mutation Framework (STCMF). By mathematically quantifying Telemetry Ignorance, it proves that current EDR solutions suffer from structural blindspots at the telemetry extraction layer, not just the heuristic layer.
