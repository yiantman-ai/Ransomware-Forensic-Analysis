# Visualization Tools

Generate visual representations of the forensic analysis.

## Requirements
```bash
pip install matplotlib numpy
```

## Usage
```bash
cd tools/visualization
python3 create_timeline_graph.py
```

## Generated Graphs

1. **timeline_graph.png** - Visual timeline of attack events
2. **phase_breakdown.png** - Pie chart of attack phases
3. **mitre_heatmap.png** - MITRE ATT&CK technique distribution
4. **network_flow.png** - Network communication diagram

## Output Location

All graphs are saved in the current directory with 300 DPI resolution.
