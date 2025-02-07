from datetime import datetime
import sys
from apt_rag_system import APTRagSystem
from ttp_rag_system import RAGSystem_ttp
from network_ttp_analyzer import NetworkTTPAnalyzer
# from network_ttp_analyzer_v2 import NetworkTTPAnalyzer
import json
import time

def getTTPs(ttps):
    res=[]
    for ttp in ttps:
        res.append(ttp["id"])
    return res
def rename_key_in_list(obj_list, old_key, new_key):
    """
    Renames a key in each dictionary of a list of dictionaries.

    Args:
        obj_list (list): List of dictionaries to process.
        old_key (str): The key to be renamed.
        new_key (str): The new key name.

    Returns:
        list: A new list of dictionaries with the key renamed.
    """
    new_list = []
    for obj in obj_list:
        # Create a new dictionary for each object
        new_obj = {}
        for key, value in obj.items():
            if key == old_key:
                new_obj[new_key] = value  # Rename the key
            else:
                new_obj[key] = value  # Keep other keys unchanged
        new_list.append(new_obj)
    return new_list


def create_report(logs,eng,networkAnalysis, ttps, apfts,timer):
    # Prepare the report object
    report_object = {
        "report": datetime.now().isoformat(),  # Timestamp of now
        "logs":logs,
        "description of logs":eng,
        "network analysis": networkAnalysis,
        "TTPs": ttps,
        "APTs": apfts,
        "Time taken for analysis":f"{timer} seconds"
    }
    
    # Read the existing data from reports.json if it exists
    try:
        with open("./data/reports.json", "r") as file:
            data = json.load(file)
    except FileNotFoundError:
        data = []  # If the file doesn't exist, start with an empty list
    
    # Append the new report to the data
    data.append(report_object)
    
    # Write the updated data back to reports.json
    with open("./data/reports.json", "w") as file:
        json.dump(data, file, indent=4)

if __name__ == "__main__":
    # initiallize timer
    start_time = time.time()
    # Initialize network anlaysis and RAG system
    # analyzer = networkAnalysis("./data/chat_history.json", "./data/few_shots.json")
    analyzer = NetworkTTPAnalyzer()
    TTPrag = RAGSystem_ttp("./data/ttp_data.json")
    APTrag = APTRagSystem("./data/apt_data.json")
    
#     network_logs=[
#   {
#     "timestamp": "2024-12-07T10:00:00.123Z",
#     "source_ip": "192.168.1.50",
#     "destination_ip": "203.0.113.100",
#     "protocol": "HTTPS",
#     "port": 443,
#     "payload": "C2 beacon: GET /tasks/update"
#   },
#   {
#     "timestamp": "2024-12-07T10:05:15.456Z",
#     "source_ip": "192.168.1.51",
#     "destination_ip": "192.168.1.10",
#     "protocol": "SMB",
#     "port": 445,
#     "payload": "NTLM authentication attempt for lateral movement"
#   },
#   {
#     "timestamp": "2024-12-07T10:10:30.789Z",
#     "source_ip": "192.168.1.52",
#     "destination_ip": "8.8.8.8",
#     "protocol": "DNS",
#     "port": 53,
#     "payload": "DNS query: exfil.domain.com (suspected data exfiltration)"
#   },
#   {
#     "timestamp": "2024-12-07T10:15:00.321Z",
#     "source_ip": "192.168.1.53",
#     "destination_ip": "203.0.113.50",
#     "protocol": "LDAP",
#     "port": 389,
#     "payload": "Query: (&(objectClass=user)(servicePrincipalName=*))"
#   },
#   {
#     "timestamp": "2024-12-07T10:20:45.654Z",
#     "source_ip": "192.168.1.54",
#     "destination_ip": "10.0.0.5",
#     "protocol": "RDP",
#     "port": 3389,
#     "payload": "Brute-force login detected"
#   },
#   {
#     "timestamp": "2024-12-07T10:25:30.987Z",
#     "source_ip": "192.168.1.55",
#     "destination_ip": "192.168.1.20",
#     "protocol": "HTTP",
#     "port": 80,
#     "payload": "File upload detected: malicious.exe"
#   },
#   {
#     "timestamp": "2024-12-07T10:30:00.567Z",
#     "source_ip": "192.168.1.56",
#     "destination_ip": "203.0.113.30",
#     "protocol": "HTTPS",
#     "port": 443,
#     "payload": "POST request: /report-status (C2 communication)"
#   },
#   {
#     "timestamp": "2024-12-07T10:35:12.890Z",
#     "source_ip": "192.168.1.57",
#     "destination_ip": "192.168.1.25",
#     "protocol": "FTP",
#     "port": 21,
#     "payload": "File exfiltration: database_dump.sql"
#   }
# ]

#     aws_logs=  [
#   {
#     "eventVersion": "1.05",
#     "userIdentity": {
#       "type": "IAMUser",
#       "userName": "admin",
#       "arn": "arn:aws:iam::123456789012:user/admin",
#       "accountId": "123456789012"
#     },
#     "eventTime": "2024-12-07T10:00:00Z",
#     "eventName": "CreateAccessKey",
#     "sourceIPAddress": "192.168.1.50",
#     "requestParameters": {
#       "userName": "admin"
#     },
#     "responseElements": {
#       "accessKey": {
#         "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
#         "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
#       }
#     }
#   },
#   {
#     "eventVersion": "1.05",
#     "userIdentity": {
#       "type": "IAMUser",
#       "userName": "admin",
#       "arn": "arn:aws:iam::123456789012:user/admin",
#       "accountId": "123456789012"
#     },
#     "eventTime": "2024-12-07T10:05:30Z",
#     "eventName": "PutRolePolicy",
#     "sourceIPAddress": "192.168.1.51",
#     "requestParameters": {
#       "roleName": "lambda-admin",
#       "policyName": "full-access",
#       "policyDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
#     }
#   },
#   {
#     "eventVersion": "1.05",
#     "userIdentity": {
#       "type": "IAMUser",
#       "userName": "admin",
#       "arn": "arn:aws:iam::123456789012:user/admin",
#       "accountId": "123456789012"
#     },
#     "eventTime": "2024-12-07T10:10:00Z",
#     "eventName": "StartInstances",
#     "sourceIPAddress": "192.168.1.52",
#     "requestParameters": {
#       "instanceIds": ["i-0abc1234de567fgh8"]
#     },
#     "responseElements": {
#       "instancesSet": {
#         "items": [
#           {
#             "instanceId": "i-0abc1234de567fgh8",
#             "currentState": {
#               "code": 16,
#               "name": "running"
#             },
#             "previousState": {
#               "code": 0,
#               "name": "pending"
#             }
#           }
#         ]
#       }
#     }
#   }
# ]


    network_logs=[
  {
    "timestamp": "2025-01-04T08:00:00.123Z",
    "source_ip": "192.168.1.100",
    "destination_ip": "10.0.0.1",
    "protocol": "HTTPS",
    "port": 443,
    "payload": "GET /login?token=abc123 (suspected token exfiltration)"
  },
  {
    "timestamp": "2025-01-04T08:10:00.456Z",
    "source_ip": "192.168.1.101",
    "destination_ip": "203.0.113.50",
    "protocol": "HTTP",
    "port": 80,
    "payload": "POST /admin/upload.php with malicious.dll (malware delivery)"
  },
  {
    "timestamp": "2025-01-04T08:20:00.789Z",
    "source_ip": "192.168.1.102",
    "destination_ip": "10.0.0.5",
    "protocol": "RDP",
    "port": 3389,
    "payload": "Brute-force login attempts detected"
  },
  {
    "timestamp": "2025-01-04T08:30:00.321Z",
    "source_ip": "10.0.0.1",
    "destination_ip": "8.8.8.8",
    "protocol": "DNS",
    "port": 53,
    "payload": "DNS query for suspicious domain: command-and-control.com"
  },
  {
    "timestamp": "2025-01-04T08:40:00.654Z",
    "source_ip": "192.168.1.103",
    "destination_ip": "192.168.1.104",
    "protocol": "SMB",
    "port": 445,
    "payload": "File access: \\share\\confidential_data.xls"
  },
  {
    "timestamp": "2025-01-04T08:50:00.567Z",
    "source_ip": "192.168.1.105",
    "destination_ip": "192.168.1.1",
    "protocol": "SNMP",
    "port": 161,
    "payload": "SNMP walk with public community string (network reconnaissance)"
  },
  {
    "timestamp": "2025-01-04T09:00:00.890Z",
    "source_ip": "192.168.1.106",
    "destination_ip": "10.0.0.10",
    "protocol": "HTTP",
    "port": 80,
    "payload": "HTTP GET request for /downloads/malicious_update.bin"
  },
  {
    "timestamp": "2025-01-04T09:10:00.123Z",
    "source_ip": "192.168.1.107",
    "destination_ip": "10.0.0.15",
    "protocol": "Kerberos",
    "port": 88,
    "payload": "TGS-REQ for MSSQLSvc/server.local"
  }
]
    
    aws_logs=[
  {
    "eventVersion": "1.05",
    "userIdentity": {
      "type": "AssumedRole",
      "principalId": "arn:aws:sts::123456789012:assumed-role/EC2Role/i-0a1b2c3d4e5f6g7h8",
      "arn": "arn:aws:iam::123456789012:role/EC2Role",
      "accountId": "123456789012"
    },
    "eventTime": "2025-01-04T08:05:00Z",
    "eventName": "AssumeRole",
    "sourceIPAddress": "192.168.1.100",
    "requestParameters": {
      "roleArn": "arn:aws:iam::123456789012:role/AdminRole",
      "roleSessionName": "malicious-session"
    },
    "responseElements": {
      "credentials": {
        "accessKeyId": "AKIA1234567890123456",
        "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      }
    }
  },
  {
    "eventVersion": "1.05",
    "userIdentity": {
      "type": "IAMUser",
      "userName": "admin",
      "arn": "arn:aws:iam::123456789012:user/admin",
      "accountId": "123456789012"
    },
    "eventTime": "2025-01-04T08:20:00Z",
    "eventName": "PutUserPolicy",
    "sourceIPAddress": "192.168.1.101",
    "requestParameters": {
      "policyName": "malicious-policy",
      "policyDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
    }
  },
  {
    "eventVersion": "1.05",
    "userIdentity": {
      "type": "IAMUser",
      "userName": "backup-user",
      "arn": "arn:aws:iam::123456789012:user/backup-user",
      "accountId": "123456789012"
    },
    "eventTime": "2025-01-04T08:50:00Z",
    "eventName": "DownloadDBSnapshot",
    "sourceIPAddress": "192.168.1.102",
    "requestParameters": {
      "snapshotId": "db-snapshot-1234",
      "targetRegion": "us-east-1"
    }
  },
  {
    "eventVersion": "1.05",
    "userIdentity": {
      "type": "IAMUser",
      "userName": "malicious-user",
      "arn": "arn:aws:iam::123456789012:user/malicious-user",
      "accountId": "123456789012"
    },
    "eventTime": "2025-01-04T09:00:00Z",
    "eventName": "CreateAccessKey",
    "sourceIPAddress": "192.168.1.105",
    "requestParameters": {
      "userName": "malicious-user"
    },
    "responseElements": {
      "accessKeyId": "AKIA9876543210987654",
      "secretAccessKey": "xAmpleK3y!p0isonEXAMPLEKEY"
    }
  },
  {
    "eventVersion": "1.05",
    "userIdentity": {
      "type": "IAMUser",
      "userName": "admin",
      "arn": "arn:aws:iam::123456789012:user/admin",
      "accountId": "123456789012"
    },
    "eventTime": "2025-01-04T09:15:00Z",
    "eventName": "StartInstances",
    "sourceIPAddress": "192.168.1.106",
    "requestParameters": {
      "instances": ["i-1234567890abcdef0"]
    },
    "responseElements": {
      "instancesSet": {
        "items": [
          {
            "instanceId": "i-1234567890abcdef0",
            "currentState": {"code": 16, "name": "running"},
            "previousState": {"code": 0, "name": "pending"}
          }
        ]
      }
    }
  }
]

    logs=network_logs+aws_logs
    # anal_res = analyzer.analyze_logs(example_logs)
    analyseNetwork = analyzer.analyze_logs(logs)
    english_description= analyseNetwork[1]   
    analyseNetwork = rename_key_in_list(analyseNetwork[0],"kill_chain_phases","kill chain phases")

    print("***************************\n",json.dumps(analyseNetwork,indent=4),"\n***************************")
    # Get similar TTPs
    similar_docs = TTPrag.find_similar_documents(analyseNetwork)
    # get list of ttps

    ttp_list = getTTPs(similar_docs)
    print("***************************\n",json.dumps(similar_docs,indent=4),"\n***************************")

    # Get matching APT groups
    # matching_groups = APTrag.find_apt_by_ttps(ttp_list)
    matching_groups = APTrag.calculate_ttp_match(similar_docs)
    # matching_groups=calculate_ttp_match()
    print("***************************\n",json.dumps(matching_groups,indent=4),"\n***************************")
    end_time = time.time()
    execution_time = end_time - start_time
    create_report(logs,english_description,analyseNetwork,similar_docs,matching_groups,execution_time)

    # print("Similar documents:", json.dumps(similar_docs, indent=2))
    # print(similar_docs)
    # print(json.dumps(matching_groups, indent=2))
    # injectHistory()

    # **************************************************************************************************************************** #
    # Optional: Query LLM with results
    # user_question = "What are the main techniques used in this attack?"
    # llm_response = rag.query_llm(user_question, similar_docs)
    # print("\nLLM Response:", llm_response)
    # print(llm_response[0])
