#!/var/ossec/framework/python/bin/python3
"""
Wazuh FIM-RDP Correlation Integration
Enriches FIM alerts with recent RDP login IPs
Place in: /var/ossec/integrations/fim-rdp-correlator
"""

import json
import sys
import requests
from datetime import datetime, timedelta
from requests.auth import HTTPBasicAuth
import urllib3
from socket import socket, AF_UNIX, SOCK_DGRAM
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============= CONFIGURATION =============
ES_URL = "http://10.0.55.15:9200"
ES_USER = "admin"
ES_PASS = "admin"
HOURS_BACK = 24
DEBUG = True  # Set to False in production
socket_addr = '/var/ossec/queue/sockets/queue'
alert_output = {}
# =========================================


def send_event(msg, agent = None):
    if not agent or agent["id"] == "000":
        string = '1:fim:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->fim-rdp-correlator:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))
    log("# Request result from MISP server: %s" % string)
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(socket_addr)
        sock.send(string.encode())
        log("# Success: Enriched event sent to Wazuh socket.")
        sock.close()
    except FileNotFoundError:
        log("# Error: Unable to open socket connection at %s" % SOCKET_ADDR)
        sys.exit(ERR_SOCKET_OPERATION)

def log(message, level="INFO"):
    """Log to Wazuh integration log"""
    if DEBUG or level == "ERROR":
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open('/var/ossec/logs/integrations.log', 'a') as f:
            f.write(f"{timestamp} fim-rdp-correlator: [{level}] {message}\n")

def query_rdp_logins(username, agent_id, hours=24):
    """Query recent RDP logins for a specific user on specific agent"""
    
    now = datetime.utcnow()
    past = now - timedelta(hours=hours)
    
    # Elasticsearch query for RDP logins (Event ID 4624, Logon Type 10)
    query = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"data.win.system.eventID": "4624"}},
                    {"match": {"data.win.eventdata.targetUserName": username}},
                    {"match": {"agent.id": agent_id}},
                    {
                        "range": {
                            "timestamp": {
                                "gte": past.isoformat(),
                                "lte": now.isoformat()
                            }
                        }
                    }
                ]
            }
        },
        "size": 100,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": [
            "data.win.eventdata.ipAddress",
            "data.win.eventdata.logonType",
            "timestamp",
            "agent.name"
        ]
    }
    
    try:
        response = requests.post(
            f"{ES_URL}/wazuh-alerts-*/_search",
            json=query,
            auth=HTTPBasicAuth(ES_USER, ES_PASS),
            verify=False,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            hits = response.json()['hits']['hits']
            
            # Extract unique IPs with timestamps
            ip_list = []
            seen_ips = set()
            
            for hit in hits:
                try:
                    ip = hit['_source']['data']['win']['eventdata']['ipAddress']
                    timestamp = hit['_source']['timestamp']
                    agent = hit['_source'].get('agent', {}).get('name', 'unknown')
                    
                    # Filter out local/invalid IPs
                    if ip not in seen_ips and ip not in ['-', '::1', '127.0.0.1', '', None]:
                        seen_ips.add(ip)
                        ip_list.append({
                            'ip': ip,
                            'timestamp': timestamp,
                            'agent': agent
                        })
                except (KeyError, TypeError):
                    continue
            
            log(f"Found {len(ip_list)} unique RDP IPs for user {username}")
            return ip_list
        else:
            log(f"ES query failed: {response.status_code} - {response.text}", "ERROR")
            return []
            
    except Exception as e:
        log(f"Failed to query RDP logins: {str(e)}", "ERROR")
        return []

def enrich_fim_alert(alert):
    """Enrich FIM alert with RDP login IPs"""
    
    try:
        # Extract username and agent ID from FIM alert
        username = None
        agent_id = alert.get('agent', {}).get('id')
        agent_name = alert.get('agent', {}).get('name', 'unknown')
        
        # Get username from whodata
        audit = alert['syscheck'].get('audit', {})
        if 'user' in audit:
            username = audit['user'].get('name')
        
        if not username:
            log("No username found in FIM alert, skipping enrichment")
            return alert
        
        if not agent_id:
            log("No agent ID found in FIM alert, skipping enrichment")
            return alert
        
        log(f"Processing FIM alert for user: {username}, agent: {agent_name} ({agent_id})")
        
        # Query recent RDP logins
        rdp_logins = query_rdp_logins(username, agent_id, HOURS_BACK)
        
        # Add correlation data to alert
        if 'data' not in alert:
            alert['data'] = {}
        alert_output['fim_rdp'] = {}
        alert_output['integration'] = 'fim-rdp-correlator'
        alert_output['fim_rdp']['rdp_correlation'] = {
            'username': username,
            'recent_rdp_ips': [login['ip'] for login in rdp_logins],
            'recent_rdp_logins': rdp_logins,
            'total_unique_ips': len(rdp_logins),
            'query_time': datetime.utcnow().isoformat(),
            'time_range_hours': HOURS_BACK,
            'file_path':alert['syscheck'].get('path'),
            'og_alert_timestamp':alert['timestamp']
        }
        
        # Update rule description with IPs
        if rdp_logins:
            ip_summary = ', '.join([login['ip'] for login in rdp_logins[:5]])
            if len(rdp_logins) > 5:
                ip_summary += f" (+{len(rdp_logins) - 5} more)"
            
            original_desc = alert['rule'].get('description', 'File modified')
            alert['rule']['description'] = (
                f"{original_desc} | User: {username} | Recent RDP IPs: {ip_summary}"
            )
            alert_output['fim_rdp']['description'] = (
                f"{original_desc} | User: {username} | Recent RDP IPs: {ip_summary}"
            )
            # Add custom field for easy filtering in dashboard
            alert_output['fim_rdp']['has_rdp_correlation'] = True
            alert_output['fim_rdp']['found'] = 1
            
            log(f"Alert enriched with {len(rdp_logins)} RDP IPs: {ip_summary}")
        else:
            alert_output['data']['has_rdp_correlation'] = False
            alert['rule']['description'] = (
                f"{alert['rule'].get('description', 'File modified')} | "
                f"User: {username} | No recent RDP logins found"
            )
            log(f"No RDP logins found for user {username} in last {HOURS_BACK} hours")
        
        return alert
        
    except Exception as e:
        log(f"Failed to enrich alert: {str(e)}", "ERROR")
        return alert

def main():
    """Main execution - called by Wazuh"""
    

    if len(sys.argv) < 2:
        return

    alert_file_path = sys.argv[1]

    try:
        # 1. Read the file content as a plain STRING first
        with open(alert_file_path, 'r') as f:
            alert_json_str = f.read()

        # 2. Write that string to your debug file
        with open("/tmp/fim-rdp-correlator.json", "a") as f:
            f.write(alert_json_str + "\n")

        # 3. Now convert it to a Python Dictionary/Object for usage
        alert = json.loads(alert_json_str)

        # Log received alert
        log(f"Received alert - Rule: {alert.get('rule', {}).get('id')}, "
            f"File: {alert.get('syscheck', {}).get('path', 'N/A')}")
        
        # Only process FIM alerts with syscheck data
        if 'syscheck' in alert.get('location', {}):
            enriched_alert = enrich_fim_alert(alert)
            with open("/tmp/enriched_debug.json", "a") as f:
                f.write(json.dumps(alert_output) + "\n")
            # Output enriched alert (Wazuh will process this)
            send_event(alert_output, alert["agent"])
            #print(json.dumps(enriched_alert))
            #sys.stdout.flush()
        else:
# 5. CRITICAL: Pass the alert back to Wazuh!
        # Even if you commented out the enrichment logic, you MUST print the original alert.
             print(alert_json_str)
             sys.stdout.flush()
            
    except json.JSONDecodeError as e:
        log(f"Invalid JSON input: {str(e)}", "ERROR")
        sys.exit(1)
    except Exception as e:
        log(f"Unexpected error: {str(e)}", "ERROR")
        sys.exit(1)

if __name__ == "__main__":
    main()
