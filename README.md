# Physical & Digital Access Control Integration Framework (v2.0)

## Project Overview

This project presents a professional-grade conceptual framework and simulation for an integrated access control system that unifies physical and digital security. The primary goal is to create a cohesive security environment where access rights are managed centrally, and data from both physical entry points (e.g., RFID keycard readers) and digital systems (e.g., Active Directory logins) are correlated for enhanced monitoring and threat detection.

This version has been significantly refactored to use **Object-Oriented Programming (OOP)**, external configuration files, and more sophisticated analysis techniques, demonstrating a higher level of software engineering practice. The framework is designed around the **Principle of Least Privilege**.

The repository includes a Python-based simulation, a multi-faceted log analyzer, a detailed vulnerability analysis, and professional documentation.

## Key Improvements in This Version

* **Object-Oriented Design:** The entire codebase is refactored into classes (`User`, `AccessPoint`, `Simulator`, `LogAnalyzer`) for better structure, scalability, and maintainability.
* **External Configuration:** User, zone, and resource definitions are externalized into `config.json`, separating data from logic.
* **Advanced Log Analysis:** The analyzer now detects more subtle threats:
    * **Impossible Travel:** Geographically impossible access patterns.
    * **Brute-Force Attempts:** Repeated failed access attempts.
    * **Anomalous Access Hours:** Access attempts outside of standard business hours.
    * **Privilege Escalation Probing:** A pattern of failed attempts against resources just above a user's authorization level.
* **Dynamic Simulation:** The simulation is more varied and realistic, generating a wider range of event types.

## How to Run the Project

### Prerequisites

* Python 3.7 or higher

### Steps

1.  **Clone the repository:**

    git clone [your-repo-link]
    cd [your-repo-name]


2.  **Run the main script:**
    The `main.py` script handles everything: it runs the simulation to generate logs and then immediately runs the analysis on those logs.

    python main.py

    The full simulation log will be saved to `logs/event_log.csv`, and the analysis report will be printed to the console.

## Project Context

This project was developed as part of the cybersecurity curriculum at California State University, Fullerton. It demonstrates a practical understanding of key software engineering and security concepts including:
* Object-Oriented Programming (OOP)
* Configuration Management
* Identity and Access Management (IAM)
* Security Information and Event Management (SIEM) Concepts
* Threat Modeling and Vulnerability Assessment
