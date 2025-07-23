from access_control.Simulator import Simulator
from access_control.analyzer import LogAnalyzer
import json

def main():
    """
    Main execution function.
    Loads configuration, runs the simulation, and then runs the log analysis.
    """
    print("--- Starting Access Control Framework v2.0 ---")

    # Load configuration
    with open('config.json', 'r') as f:
        config = json.load(f)

    # 1. Run the Simulation
    print("\n[PHASE 1] Running Simulation...")
    simulator = Simulator(config)
    simulator.run_full_simulation()
    print(f"Simulation complete. Log file generated at '{simulator.log_file_path}'.")

    # 2. Run the Analysis
    print("\n[PHASE 2] Analyzing Logs...")
    analyzer = LogAnalyzer(simulator.log_file_path)
    analyzer.generate_report()
    
    print("\n--- Framework Execution Finished ---")

if __name__ == "__main__":
    main()