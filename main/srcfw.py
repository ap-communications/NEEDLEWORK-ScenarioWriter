import ipaddress

from main import absorbdict
from main import multiple

src_fw = []

# src-fwのリストの生成


# [x['Value'] for x in list if x['Key'] == 'Name']
# TODO:一つのゾーンが複数のIFに割り当てられていてかつIPがIF数分振られていない時の処理を考える
def decide_src_fw(policy, append_list, src_if):
    for i in absorbdict.ifinfo:
        if src_if in i['IF_Name']:
            data = str(i['IP'].split('/')[0])
            if data != 'None':
                multiple.handle_multiple_ip(
                    policy, append_list, data)
    

def handle_src_fw():
    global src_fw
    append_list = src_fw
    for policy in absorbdict.policy_dict:
        flag = False
        for i in absorbdict.ifinfo:
            if "VIP(" in policy['src_ip']:
                flag = True
                for vip_c in absorbdict.vip_dict:
                    if policy['src_ip'].strip(')"').split('(')[1] == vip_c['global_ip']:
                        longest_match = {}
                        for if_ip_c in absorbdict.route_dict:
                            if ipaddress.ip_address(vip_c['private_ip']) in ipaddress.ip_network(if_ip_c['network_address'], strict=False):
                                a = {
                                    if_ip_c['if_name']: if_ip_c['network_address'].split('/')[1]}
                                longest_match.update(a)
                            else:
                                continue
                        max_keys = max(longest_match, key=longest_match.get)
                        src_if = max_keys.replace('"', '')
                        decide_src_fw(policy, append_list, src_if)
                        break
                    elif policy['src_ip'].strip(')"').split('(')[1] == vip_c['if_name'] and vip_c['global_ip'] == "interface-ip":
                        src_if = policy['src_ip'].strip(')"').split('(')[1].replace('"', '')
                        decide_src_fw(policy, append_list, src_if)
                        break
                break
            elif policy['src_zone'] == i['Zone'] and i['IP'] != 'None':
                flag = True
                src_if = i['IF_Name']
                decide_src_fw(policy, append_list, src_if)
        else:
            if not flag:
                #zoneにIPアドレスが設定されていない場合、テストシナリオのsrc-fwにzone名を記載する
                data = str(policy['src_zone'])
                multiple.handle_multiple_ip(
                    policy, append_list, data)
   



handle_src_fw()

# print('srcfw : %s' % (len(src_fw)))
