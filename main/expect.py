import ipaddress

from main import absorbdict
from main import multiple

expect = []
expect_icmp = []

# exceptのリストの生成


def judge_default_expect(policy, append_list):
    if 'permit' == policy['expect']:
        data = str("pass")
        multiple.handle_multiple_ip(policy, append_list, data)#2673
    else:
        data = str("drop")
        multiple.handle_multiple_ip(policy, append_list, data)#660 + 10


# PINGまたはICMP-ANYが前のポリシーで使用されていると想定と異なる結果となるためスキップする
# ただし前のポリシーが出力されていることを確認する
def confirm_service_name_ping(policy, service_name_list):
    append_list = expect_icmp
    for service_name_list_c in service_name_list:
        if service_name_list_c == '"PING"' or service_name_list_c == '"ICMP-ANY"':
            data = str("NaN")
            print('前のポリシーで出力しているためpolicy_id = %sではicmpのポリシーの出力をスキップします' %
                  policy['policy_id'])
            multiple.handle_multiple_ip(policy, append_list, data)
            break
    else:
        # TODO:その他も見る必要があれば修正する
        judge_default_expect(policy, append_list)


def implicit_rule_icmp_expect(policy):
    service_name_list = []
    for pre_policy in absorbdict.policy_dict:
        if policy['src_zone'] == pre_policy['src_zone'] and policy['dst_zone'] == pre_policy['dst_zone']:
            if len(absorbdict.group_service_dict) >= 2:
                flag = False
                for group_service_c in absorbdict.group_service_dict:
                    if pre_policy['protocol'] == group_service_c['group_service_name']:
                        flag = True
                        service_name_list += [group_service_c['service_name']]
                        continue
                else:
                    if not flag:
                        service_name_list += [pre_policy['protocol']]
            elif pre_policy['protocol'] == '"ANY"':
                continue
            else:
                service_name_list += [pre_policy['protocol']]
            continue
        elif policy['policy_id'] == pre_policy['policy_id']:
            pass
    else:
        confirm_service_name_ping(policy, service_name_list)


def after_src_zone(policy, after_src_if, append_list):
    for if_zone in absorbdict.if_zone_dict:
        if after_src_if == if_zone['if_name'].replace('"', ''):
            src_zone = if_zone['zone_name']
            for zone_block_c in absorbdict.zone_block_dict:
                # src_zoneとdst_zoneが同一の場合blockの設定があるかで想定結果が異なる
                if src_zone == policy['dst_zone'] == zone_block_c['zone_name']:
                    data = str("drop")
                    multiple.handle_multiple_ip(policy, append_list, data)
                    break
            else:
                judge_default_expect(policy, append_list)


def after_dst_zone(policy, after_dst_if, append_list):
    for if_zone in absorbdict.if_zone_dict:
        if after_dst_if == if_zone['if_name'].replace('"', ''):
            dst_zone = if_zone['zone_name']
            for zone_block_c in absorbdict.zone_block_dict:
                # src_zoneとdst_zoneが同一の場合blockの設定があるかで想定結果が異なる
                if dst_zone == policy['src_zone'] == zone_block_c['zone_name']:
                    data = str("drop")
                    multiple.handle_multiple_ip(policy, append_list, data)
                    break
            else:
                judge_default_expect(policy, append_list)


def same_zone_block(policy, append_list):
    for zone_block_c in absorbdict.zone_block_dict:
        if zone_block_c['zone_name'] == policy['src_zone'] == policy['dst_zone']:
            data = str("drop")
            multiple.handle_multiple_ip(policy, append_list, data)
            break
    else:
        judge_default_expect(policy, append_list)


def decide_after_src_if(policy, src_ip):
    global after_src_if
    longest_match = {}
    for if_ip_c in absorbdict.route_dict:
        if ipaddress.ip_address(src_ip) in ipaddress.ip_network(if_ip_c['network_address'], strict=False):
            a = {if_ip_c['if_name']: if_ip_c['network_address'].split('/')[1]}
            longest_match.update(a)
    max_keys = max(longest_match, key=longest_match.get)
    after_src_if = max_keys
    return after_src_if


def decide_after_dst_if(policy, dst_ip):
    global after_dst_if
    longest_match = {}
    for if_ip_c in absorbdict.route_dict:
        if ipaddress.ip_address(dst_ip) in ipaddress.ip_network(if_ip_c['network_address'], strict=False):
            a = {if_ip_c['if_name']: if_ip_c['network_address'].split('/')[1]}
            longest_match.update(a)
    max_keys = max(longest_match, key=longest_match.get)
    after_dst_if = max_keys
    return after_dst_if


def handle_expect_of_changed_if(policy, append_list):
    global after_dst_if
    if policy.get('dst_nat_ip') is not None:
        dst_ip = policy['dst_nat_ip']
        decide_after_dst_if(policy, dst_ip)
        after_dst_zone(policy, after_dst_if, append_list)
    # vip時はprivate_ipのifがsrc_zoneとなる
    elif "VIP(" in policy['src_ip']:
        for vip_c in absorbdict.vip_dict:
            if policy['src_ip'].strip(')"').split('(')[1] == vip_c['global_ip']:
                src_ip = vip_c['private_ip']
                decide_after_src_if(policy, src_ip)
                after_src_zone(policy, after_src_if, append_list)
                break
            elif policy['src_ip'].strip(')"').split('(')[1] == vip_c['if_name'] and vip_c['global_ip'] == "interface-ip":
                src_ip = vip_c['private_ip']
                decide_after_src_if(policy, src_ip)
                after_src_zone(policy, after_src_if, append_list)
                break
    # vip時はprivate_ipのifがdst_zoneとなる
    # TODO:ここに吸収されてるためその他も含めて修正する
    elif "VIP(" in policy['dst_ip']:
        for vip_c in absorbdict.vip_dict:
            if policy['dst_ip'].strip(')"').split('(')[1] == vip_c['global_ip']:
                dst_ip = vip_c['private_ip']
                decide_after_dst_if(policy, dst_ip)
                after_dst_zone(policy, after_dst_if, append_list)
                break
            elif policy['dst_ip'].strip(')"').split('(')[1] == vip_c['if_name'] and vip_c['global_ip'] == "interface-ip":
                dst_ip = vip_c['private_ip']
                decide_after_dst_if(policy, dst_ip)
                after_dst_zone(policy, after_dst_if, append_list)
                break
    elif policy['src_zone'] == policy['dst_zone']:
        same_zone_block(policy, append_list)
    else:
        judge_default_expect(policy, append_list)


def handle_expect():
    global expect
    append_list = expect
    for policy in absorbdict.policy_dict:
        handle_expect_of_changed_if(policy, append_list)


# PINGがAny Any ANYのポリシー前で使用されていると想定と異なるため分けて出力する
def handle_expect_icmp():
    global expect_icmp
    append_list = expect_icmp
    for policy in absorbdict.policy_dict:
        if policy['src_ip'] == policy['dst_ip'] == '"Any"' and policy['protocol'] == '"ANY"':
            implicit_rule_icmp_expect(policy)
        else:
            handle_expect_of_changed_if(policy, append_list)


handle_expect()
handle_expect_icmp()
