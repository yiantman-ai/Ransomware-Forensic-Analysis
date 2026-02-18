#!/usr/bin/env python3
"""
Timeline Visualization Tool
Generate visual timeline of the ransomware attack

Author: Jesse Antman
Case: RANSOMWARE_21a34484
"""

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime, timedelta
import json

# Attack timeline data
TIMELINE = [
    {"time": "12:49:38", "event": "Phishing Page Access", "phase": "Initial Access", "severity": "medium"},
    {"time": "12:49:55", "event": "PowerShell Opens (User)", "phase": "Execution", "severity": "medium"},
    {"time": "12:50:51", "event": "Malicious PowerShell Execution", "phase": "Execution", "severity": "critical"},
    {"time": "12:50:51", "event": "Loader.ps1 Download", "phase": "C2", "severity": "high"},
    {"time": "12:50:51", "event": "Config.dat Download (18.6MB)", "phase": "C2", "severity": "high"},
    {"time": "12:50:51", "event": "Ransomware Execution", "phase": "Execution", "severity": "critical"},
    {"time": "12:50:52", "event": "Child Process Spawned", "phase": "Execution", "severity": "high"},
    {"time": "12:50:56", "event": "C2 Registration", "phase": "C2", "severity": "critical"},
    {"time": "12:51:06", "event": "Data Exfiltration", "phase": "Exfiltration", "severity": "critical"},
    {"time": "12:51:47", "event": "Persistence Creation", "phase": "Persistence", "severity": "high"},
]

def parse_time(time_str):
    """Convert time string to datetime"""
    base_date = datetime(2026, 2, 15)
    hour, minute, second = map(int, time_str.split(':'))
    return base_date.replace(hour=hour, minute=minute, second=second)

def create_timeline_graph():
    """Create visual timeline of attack"""
    
    # Parse times
    times = [parse_time(event["time"]) for event in TIMELINE]
    events = [event["event"] for event in TIMELINE]
    
    # Color by severity
    colors = {
        "critical": "#d32f2f",  # Red
        "high": "#f57c00",      # Orange
        "medium": "#fbc02d",    # Yellow
        "low": "#388e3c"        # Green
    }
    event_colors = [colors[event["severity"]] for event in TIMELINE]
    
    # Create figure
    fig, ax = plt.subplots(figsize=(14, 8))
    
    # Plot events
    y_positions = list(range(len(TIMELINE)))
    ax.scatter(times, y_positions, c=event_colors, s=200, alpha=0.7, edgecolors='black', linewidth=2)
    
    # Add event labels
    for i, (time, event, color) in enumerate(zip(times, events, event_colors)):
        ax.text(time, i, f"  {event}", va='center', fontsize=10, fontweight='bold')
    
    # Formatting
    ax.set_yticks(y_positions)
    ax.set_yticklabels([])
    ax.set_xlabel('Time (UTC)', fontsize=12, fontweight='bold')
    ax.set_title('Ransomware Attack Timeline - Case 21a34484\nFebruary 15, 2026', 
                 fontsize=16, fontweight='bold', pad=20)
    
    # Format x-axis
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    ax.xaxis.set_major_locator(mdates.SecondLocator(interval=30))
    plt.xticks(rotation=45)
    
    # Grid
    ax.grid(True, alpha=0.3, axis='x')
    ax.set_ylim(-1, len(TIMELINE))
    
    # Legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor=colors['critical'], label='Critical'),
        Patch(facecolor=colors['high'], label='High'),
        Patch(facecolor=colors['medium'], label='Medium')
    ]
    ax.legend(handles=legend_elements, loc='upper left', fontsize=10)
    
    # Duration annotation
    total_duration = (times[-1] - times[0]).total_seconds()
    ax.text(0.5, -0.15, f'Total Attack Duration: {int(total_duration)} seconds (~90 sec from download to exfil)',
            transform=ax.transAxes, ha='center', fontsize=11, 
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
    plt.tight_layout()
    plt.savefig('timeline_graph.png', dpi=300, bbox_inches='tight')
    print("[+] Timeline graph saved: timeline_graph.png")
    plt.close()

def create_phase_breakdown():
    """Create pie chart of attack phases"""
    
    phases = {}
    for event in TIMELINE:
        phase = event["phase"]
        phases[phase] = phases.get(phase, 0) + 1
    
    fig, ax = plt.subplots(figsize=(10, 8))
    
    colors_pie = ['#d32f2f', '#f57c00', '#fbc02d', '#388e3c', '#1976d2']
    wedges, texts, autotexts = ax.pie(
        phases.values(), 
        labels=phases.keys(),
        autopct='%1.1f%%',
        startangle=90,
        colors=colors_pie,
        textprops={'fontsize': 12, 'fontweight': 'bold'}
    )
    
    ax.set_title('Attack Phases Distribution\nCase 21a34484', 
                 fontsize=16, fontweight='bold', pad=20)
    
    plt.tight_layout()
    plt.savefig('phase_breakdown.png', dpi=300, bbox_inches='tight')
    print("[+] Phase breakdown saved: phase_breakdown.png")
    plt.close()

def create_mitre_heatmap():
    """Create MITRE ATT&CK heatmap"""
    
    tactics = [
        'Initial\nAccess', 'Execution', 'Persistence', 'Defense\nEvasion',
        'Credential\nAccess', 'Discovery', 'Collection', 'C2', 'Exfiltration', 'Impact'
    ]
    
    technique_counts = [1, 2, 2, 4, 2, 4, 2, 3, 2, 3]
    
    fig, ax = plt.subplots(figsize=(14, 6))
    
    colors_map = plt.cm.Reds([(x/max(technique_counts)) for x in technique_counts])
    bars = ax.bar(tactics, technique_counts, color=colors_map, edgecolor='black', linewidth=2)
    
    # Add value labels
    for bar, count in zip(bars, technique_counts):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{count}',
                ha='center', va='bottom', fontsize=12, fontweight='bold')
    
    ax.set_ylabel('Number of Techniques', fontsize=12, fontweight='bold')
    ax.set_title('MITRE ATT&CK Technique Distribution\n25 Techniques Identified', 
                 fontsize=16, fontweight='bold', pad=20)
    ax.set_ylim(0, max(technique_counts) + 1)
    ax.grid(True, alpha=0.3, axis='y')
    
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig('mitre_heatmap.png', dpi=300, bbox_inches='tight')
    print("[+] MITRE heatmap saved: mitre_heatmap.png")
    plt.close()

def create_network_flow():
    """Create network traffic visualization"""
    
    fig, ax = plt.subplots(figsize=(12, 8))
    
    # Nodes
    victim_x, victim_y = 2, 5
    c2_x, c2_y = 8, 5
    
    # Draw nodes
    victim_circle = plt.Circle((victim_x, victim_y), 0.5, color='#1976d2', alpha=0.7)
    c2_circle = plt.Circle((c2_x, c2_y), 0.5, color='#d32f2f', alpha=0.7)
    ax.add_patch(victim_circle)
    ax.add_patch(c2_circle)
    
    # Labels
    ax.text(victim_x, victim_y, 'Victim\n192.168.74.157', ha='center', va='center', 
            fontsize=10, fontweight='bold', color='white')
    ax.text(c2_x, c2_y, 'C2 Server\n192.168.74.147:8080', ha='center', va='center',
            fontsize=10, fontweight='bold', color='white')
    
    # Arrows (communications)
    communications = [
        {"y": 6.5, "label": "1. GET / (Phishing)", "color": "#fbc02d", "direction": "→"},
        {"y": 6.0, "label": "2. GET /loader.ps1 (868 B)", "color": "#f57c00", "direction": "→"},
        {"y": 5.5, "label": "3. GET /config.dat (18.6 MB)", "color": "#f57c00", "direction": "→"},
        {"y": 4.5, "label": "4. POST /register (Key + Info)", "color": "#d32f2f", "direction": "→"},
        {"y": 4.0, "label": "5. POST /exfiltrate (37 files)", "color": "#d32f2f", "direction": "→"},
    ]
    
    for comm in communications:
        ax.annotate('', xy=(c2_x-0.5, comm["y"]), xytext=(victim_x+0.5, comm["y"]),
                   arrowprops=dict(arrowstyle='->', lw=2, color=comm["color"]))
        ax.text((victim_x + c2_x)/2, comm["y"]+0.2, comm["label"],
               ha='center', fontsize=9, bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))
    
    ax.set_xlim(0, 10)
    ax.set_ylim(3, 7.5)
    ax.set_aspect('equal')
    ax.axis('off')
    ax.set_title('Network Communication Flow\nCase 21a34484', 
                 fontsize=16, fontweight='bold', pad=20)
    
    plt.tight_layout()
    plt.savefig('network_flow.png', dpi=300, bbox_inches='tight')
    print("[+] Network flow saved: network_flow.png")
    plt.close()

def main():
    print("=" * 70)
    print("Timeline Visualization Tool")
    print("=" * 70)
    print()
    
    try:
        print("[*] Creating timeline graph...")
        create_timeline_graph()
        
        print("[*] Creating phase breakdown...")
        create_phase_breakdown()
        
        print("[*] Creating MITRE heatmap...")
        create_mitre_heatmap()
        
        print("[*] Creating network flow diagram...")
        create_network_flow()
        
        print()
        print("=" * 70)
        print(" All visualizations created successfully!")
        print("=" * 70)
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
