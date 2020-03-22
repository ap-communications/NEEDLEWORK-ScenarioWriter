from main import absorbdict
from main import multiple

dst_vlan = []

# src-vlanのリストの生成


def handle_dst_vlan():
    global dst_vlan
    append_list = dst_vlan
    for policy in absorbdict.policy_dict:
        for if_zone in absorbdict.if_zone_dict:
            if policy['dst_zone'] == if_zone['zone_name'] and if_zone.get('vlan_num') is not None:
                data = str(if_zone['vlan_num'])
                multiple.handle_multiple_ip(policy, append_list, data)
                break
        else:
            data = str("")
            multiple.handle_multiple_ip(policy, append_list, data)


handle_dst_vlan()
