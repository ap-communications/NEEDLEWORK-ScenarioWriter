import ipaddress

from main import absorbdict
from main import multiple

dst_fw = []

# dst-fwのリストの生成


# TODO:一つのゾーンが複数のIFに割り当てられていてかつIPがIF数分振られていない時の処理を考える
def decide_dst_fw(policy, append_list, dst_if):
    for i in absorbdict.ifinfo:
        if dst_if in i['IF_Name']:
            data = str(i['IP'].split('/')[0])
            if data != 'None':
                multiple.handle_multiple_ip(
                    policy, append_list, data)


def handle_dst_fw():
    global dst_fw
    append_list = dst_fw
    for policy in absorbdict.policy_dict:
        flag = False
        for i in absorbdict.ifinfo:
            if policy.get('dst_nat_ip') is not None:
                flag = True
                longest_match = {}
                for if_ip_c in absorbdict.route_dict:
                    if ipaddress.ip_address(policy['dst_nat_ip']) in ipaddress.ip_network(if_ip_c['network_address'], strict=False):
                        a = {if_ip_c['if_name']: if_ip_c['network_address'].split('/')[1]}
                        longest_match.update(a)
                        max_keys = max(longest_match, key=longest_match.get)
                    else:
                        continue
                dst_if = max_keys.replace('"', '')
                decide_dst_fw(policy, append_list, dst_if)
                break
            elif "VIP(" in policy['dst_ip']:
                flag = True
                for vip_c in absorbdict.vip_dict:
                    if policy['dst_ip'].strip(')"').split('(')[1] == vip_c['global_ip']:
                        longest_match = {}
                        for if_ip_c in absorbdict.route_dict:
                            if ipaddress.ip_address(vip_c['private_ip']) in ipaddress.ip_network(if_ip_c['network_address'], strict=False):
                                a = {
                                    if_ip_c['if_name']: if_ip_c['network_address'].split('/')[1]}
                                longest_match.update(a)
                            else:
                                continue
                        max_keys = max(longest_match, key=longest_match.get)
                        dst_if = max_keys.replace('"', '')
                        decide_dst_fw(policy, append_list, dst_if)
                        break
                    elif policy['dst_ip'].strip(')"').split('(')[1] == vip_c['if_name'] and vip_c['global_ip'] == "interface-ip":
                        dst_if = policy['dst_ip'].strip(')"').split(
                            '(')[1].replace('"', '')
                        decide_dst_fw(policy, append_list, dst_if)
                        break
                break
            elif policy['dst_zone'] == i['Zone'] and i['IP'] != 'None':
                flag = True
                dst_if = i['IF_Name']
                decide_dst_fw(policy, append_list, dst_if)
        else:
            if not flag:
                # zoneにIPアドレスが設定されていない場合、テストシナリオのdst-fwにzone名を記載する
                data = str(policy['dst_zone'])
                multiple.handle_multiple_ip(
                    policy, append_list, data)


handle_dst_fw()
