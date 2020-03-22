from main import absorbdict
from main import multiple
src_vlan = []

# src-vlanのリストの生成


def handle_src_vlan():
    global src_vlan
    append_list = src_vlan
    for policy in absorbdict.policy_dict:
        for if_zone in absorbdict.if_zone_dict:
            if policy['src_zone'] == if_zone['zone_name'] and if_zone.get('vlan_num') is not None:
                data = str(if_zone['vlan_num'])
                multiple.handle_multiple_ip(policy, append_list, data)
                break
        else:
            data = str("")
            multiple.handle_multiple_ip(policy, append_list, data)


handle_src_vlan()
