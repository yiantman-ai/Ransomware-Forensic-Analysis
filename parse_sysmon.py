#!/usr/bin/env python3
"""
Parse Sysmon EVTX and extract key events
"""
import Evtx.Evtx as evtx
import Evtx.Views as e_views
import sys
import json
from datetime import datetime
import xml.etree.ElementTree as ET

def parse_event(record):
    """Parse a single event record"""
    try:
        xml = record.xml()
        root = ET.fromstring(xml)
        
        # Namespace
        ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        
        system = root.find('ns:System', ns)
        event_id = system.find('ns:EventID', ns).text if system.find('ns:EventID', ns) is not None else 'Unknown'
        time_created = system.find('ns:TimeCreated', ns).get('SystemTime') if system.find('ns:TimeCreated', ns) is not None else 'Unknown'
        
        event_data = {}
        event_data_elem = root.find('ns:EventData', ns)
        if event_data_elem is not None:
            for data in event_data_elem.findall('ns:Data', ns):
                name = data.get('Name')
                value = data.text
                if name and value:
                    event_data[name] = value
        
        return {
            'EventID': event_id,
            'TimeCreated': time_created,
            'EventData': event_data
        }
    except Exception as e:
        return None

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 parse_sysmon.py <evtx_file>")
        sys.exit(1)
    
    evtx_file = sys.argv[1]
    
    print(f"[*] Parsing {evtx_file}...")
    
    events = {
        'ProcessCreate': [],
        'NetworkConnect': [],
        'FileCreate': [],
        'RegistryEvent': []
    }
    
    with evtx.Evtx(evtx_file) as log:
        for record in log.records():
            event = parse_event(record)
            if not event:
                continue
            
            event_id = event['EventID']
            
            # Event 1 - Process Create
            if event_id == '1':
                events['ProcessCreate'].append(event)
            
            # Event 3 - Network Connection
            elif event_id == '3':
                events['NetworkConnect'].append(event)
            
            # Event 11 - File Create
            elif event_id == '11':
                events['FileCreate'].append(event)
            
            # Event 12, 13, 14 - Registry
            elif event_id in ['12', '13', '14']:
                events['RegistryEvent'].append(event)
    
    print(f"\n[+] Parsing complete!")
    print(f"    Process Create: {len(events['ProcessCreate'])}")
    print(f"    Network Connect: {len(events['NetworkConnect'])}")
    print(f"    File Create: {len(events['FileCreate'])}")
    print(f"    Registry Events: {len(events['RegistryEvent'])}")
    
    # Save to JSON
    output_file = 'analysis/logs/sysmon_parsed.json'
    with open(output_file, 'w') as f:
        json.dump(events, f, indent=2)
    
    print(f"\n[+] Results saved to: {output_file}")
    
    return events

if __name__ == '__main__':
    events = main()
