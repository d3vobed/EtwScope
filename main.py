import argparse
import sys
import os

# Ensure the local modules can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from frontend.app import ETWScopeApp

def main():
    parser = argparse.ArgumentParser(description="ETWScope: Windows Telemetry Research Platform")
    parser.add_argument("--mock", help="Path to JSON file to stream", required=True)
    parser.add_argument("--backend", help="Path to rust backend executable", default="backend/target/release/etwscope_backend")
    
    args = parser.parse_args()

    # Construct the backend command
    cmd = f"{args.backend} --mock {args.mock}"
    
    app = ETWScopeApp(backend_cmd=cmd, rules_dir="rules")
    app.run()

if __name__ == "__main__":
    main()
