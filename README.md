# vmware_vds_traffic_filter
VMware vDS traffic filtering scripts


**READ MORE AT: https://livio.zanol.com.br/vmware-vds-traffic-filter**


`list_vds_portgroup_rules.py` list rules for a specific portgroup. You pass dvswitch name, portgroup name and rule_id (optional) as argument to the script and all rules for that portgroup is outputed on a JSON formatted string.

`edit_vds_portgroup_rules.py` edit, create and delete rules for a specific portgroup using a JSON file as source. The JSON file needs to have specific format. On the follow example we intended to create a simple TCP rule on port 53 to google DNS. Keep in mind that [protocol number must follow IANA definition](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml): (this example is also on script help):
```JSON
[
    {
    "sourceAddress":"any",
    "destinationAddress":"8.8.8.8/32",
    "sourcePort":"1024-60000",
    "destinationPort":"53",
    "protocol":"6",
    "action":"accept",
    "direction":"both",
    "description":"DNS google"
    }
]
```
