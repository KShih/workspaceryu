import requests
import sys
# curl -X PUT http://localhost:8080/firewall/module/enable/0000000000000001  Open
# curl http://localhost:8080/firewall/module/status                          CheckStatus
# curl http://localhost:8080/firewall/rules/0000000000000001                 DumpRules

# curl -X POST -d '{"nw_src": "10.0.0.1/32", "nw_dst": "10.0.0.2/32", "nw_proto": "ICMP"}' http://localhost:8080/firewall/rules/0000000000000001

# curl -X DELETE -d '{"rule_id": "5"}' http://localhost:8080/firewall/rules/0000000000000001

# -------------------------------------------------------------------------------------------#
while(1):
  SRC = raw_input('Enter Source IP : ')
  DST = raw_input('Enter Destination IP : ')
  PROTO = raw_input('Enter Protocal : ')

  rule = {"nw_src" : SRC,"nw_dst" : DST,"nw_proto" : PROTO}

  set_rule1 = requests.post("http://localhost:8080/firewall/rules/0000000000000001", json= rule)





