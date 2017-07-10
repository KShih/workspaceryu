import requests

proxies = {
  "http": "http://localhost:6633",
}

switch = {"tcp" : "192.168.87.101:6632"}
rate = {"port_name": "s1-eth1", 
        "type": "linux-htb", 
        "max_rate": "1000000", 
        "queues":[{"max_rate": "500000"}, {"min_rate": "400000"}] 
        }
rule = {
        "match": {"nw_dst": "10.0.0.1"} or {"nw_proto": "UDP"} or {"tp_dst": "5002"}, # ?????? try "or" and work!!?
        "actions": {"queue": "1"}
        }
# curl -X PUT -d '"tcp:192.168.87.101:6632"' http://localhost:8080/v1.0/conf/switches/0000000000000001/ovsdb_addr
# curl -X POST -d '{"port_name": "s1-eth1", "type": "linux-htb", "max_rate": "1000000", "queues": [{"max_rate": "500000"}, {"min_rate": "400000"}]}' http://localhost:8080/qos/queue/0000000000000001
# curl -X POST -d '{"match": {"nw_dst": "10.0.0.1", "nw_proto": "UDP", "tp_dst": "5002"}, "actions":{"queue": "1"}}' http://localhost:8080/qos/rules/0000000000000001

set_ovsdb_addr = requests.put("http://localhost:8080/v1.0/conf/switches/0000000000000001/ovsdb_addr",data= switch)
set_qos_rate = requests.post("http://localhost:8080/qos/queue/0000000000000001",json= rate) # Can't Use data type in POST
set_rule = requests.post("http://localhost:8080/qos/rules/0000000000000001", json= rule)
get_rule = requests.get("http://localhost:8080/qos/rules/0000000000000001")

print(set_qos_rate.text)
print(set_rule.text)
print(get_rule.text)
