import requests
import sys
# curl -X PUT http://localhost:8080/firewall/module/enable/0000000000000001  Open
# curl http://localhost:8080/firewall/module/status                          CheckStatus
# curl http://localhost:8080/firewall/rules/0000000000000001                 DumpRules

# curl -X POST -d '{"nw_src": "10.0.0.1/32", "nw_dst": "10.0.0.2/32", "nw_proto": "ICMP"}' http://localhost:8080/firewall/rules/0000000000000001

# curl -X DELETE -d '{"rule_id": "5"}' http://localhost:8080/firewall/rules/0000000000000001

# -------------------------------------------------------------------------------------------#

def add_entry():
    while(1):
      SRC = raw_input('Enter Source IP : ')
      DST = raw_input('Enter Destination IP : ')
      PROTO = raw_input('Enter Protocal : ')
      PRIORITY = raw_input('Enter Priority (0 - 65533) : ')  
      if (PROTO == ""):
        PROTO = "ICMP"
      if (PRIORITY == ""):
        PRIORITY = "1"
      print PROTO
      print PRIORITY
      rule = {"nw_src" : SRC,"nw_dst" : DST,"nw_proto" : PROTO,"priority" : PRIORITY}
      set_rule1 = requests.post("http://localhost:8080/firewall/rules/0000000000000001", json= rule)




print ("[A]AddEntry , [B]BlockEntry , [D]DelelteEntry , [S]ShowEntrys")
action = raw_input('Enter your Action : ')

if (action == "A"):
  add_entry()

