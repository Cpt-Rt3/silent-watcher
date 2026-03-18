Built by Ruben Treviño Rt3 — Cybersecurity Graduate Student

🛡️ Silent Watcher — SSH Log Analyzer

A Python-based security tool designed to detect suspicious SSH login activity, including brute-force attacks, and generate structured alert reports.

🔍 What it does

Parses SSH authentication logs

Detects:

Failed login attempts

Successful logins

Brute-force attack patterns

Classifies alerts by severity:

HIGH → brute-force detected

MEDIUM → suspicious activity

INFO → successful logins

Generates timestamped alert reports

Outputs daily log files for incident tracking

⚙️ How it works

Reads log file (sample_auth.log)

Uses regex to extract login attempts

Tracks failed attempts per IP

Flags IPs exceeding threshold as brute-force

Generates structured alerts with timestamps

Saves results to:

alerts_YYYY-MM-DD.txt
Sample Output
[2026-03-18 14:22:01] HIGH - Brute force detected from 10.0.0.99 (5 attempts)
[2026-03-18 14:22:05] MEDIUM - Failed login attempt detected: user=root, ip=192.168.1.50
[2026-03-18 14:22:10] INFO - Successful login: user=admin, ip=10.0.0.1

Why this matters

This project demonstrates:

Log analysis (core SOC skill)

Threat detection logic

Pattern recognition for brute-force attacks

Structured alert generation

Basic incident response thinking

Future Improvements

Real-time monitoring (tail -f)

Email / Slack alert integration

Dashboard visualization (Grafana)

Integration with SIEM tools
