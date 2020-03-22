from main import absorbdict
from main import multiple

import ipaddress

src_nat_ip = []

# src-nat-ipのリストの生成


def handle_src_nat_ip_is_dst_fw(policy, append_list, dst_if):
    for if_ip_c in absorbdict.if_ip_dict:
        if dst_if.replace('"', '') == if_ip_c['if_name'].replace('"', '') and if_ip_c.get('ip_address') is not None:
            flag = True
            dst_fw = if_ip_c['ip_address'].split('/')[0]
            data = str(dst_fw)
            multiple.handle_multiple_ip(
                policy, append_list, data)
    return flag


def handle_src_and_dst_nat(policy, append_list):
    # かつロンゲストマッチになるように実装する
    address = str(policy['dst_nat_ip'])
    ip_network = ipaddress.ip_network(
        ipaddress.ip_address(address), strict=False)
    for route_c in absorbdict.route_dict:
        routing_network = ipaddress.ip_network(
            route_c['network_address'])
        if ip_network.subnet_of(routing_network) is True:
            dst_if = route_c['if_name']
            handle_src_nat_ip_is_dst_fw(policy, append_list, dst_if)


def handle_nat_if(policy, append_list):
    global flag
    flag = False
    for if_zone in absorbdict.if_zone_dict:
        if policy['src_zone'] == if_zone['zone_name']:
            src_if = if_zone['if_name']
            for if_nat_c in absorbdict.if_nat_dict:
                if src_if.replace('"', '') == if_nat_c['if_name'].replace('"', ''):
                    flag = True
                    for if_zone in absorbdict.if_zone_dict:
                        if policy['dst_zone'] == if_zone['zone_name']:
                            dst_if = if_zone['if_name']
                            handle_src_nat_ip_is_dst_fw(
                                policy, append_list, dst_if)
            else:
                # TODO:その他の法則性があれば修正する
                # if policy['protocol'] == '"NTP"' or policy['protocol'] == '"HTTP"':
                dst_zone = policy['dst_zone']
                handle_src_nat_ip_is_mip(policy, append_list, dst_zone)
                # for address_c in absorbdict.address_dict:
                #    if policy['src_ip'].replace('"', '') == address_c['address_name'].replace('"', ''):
                #        ip_address = address_c['ip_address']
                #        for mip_c in absorbdict.mip_dict:
                #            if ip_address == mip_c['global_ip']:
                #                flag = True
                #                data = str(mip_c['private_ip'])
                #                multiple.handle_multiple_ip(
                #                    policy, append_list, data)
    return flag


def handle_src_nat_ip_is_mip(policy, append_list, dst_zone):
    global flag
    for if_zone in absorbdict.if_zone_dict:
        if dst_zone == if_zone['zone_name']:
            dst_if = if_zone['if_name']
            for address_c in absorbdict.address_dict:
                if policy['src_ip'].replace('"', '') == address_c['address_name'].replace('"', ''):
                    ip_address = address_c['ip_address']
                    for mip_c in absorbdict.mip_dict:
                        if ip_address == mip_c['global_ip'] and dst_if == mip_c['if_name']:
                            flag = True
                            data = str(mip_c['private_ip'])
                            multiple.handle_multiple_ip(
                                policy, append_list, data)


def handle_src_nat_ip():
    global src_nat_ip
    append_list = src_nat_ip
    for policy in absorbdict.policy_dict:
        if policy.get('src') is not None and policy.get('src_nat_ip') is not None:
            data = str(policy['src_nat_ip'])
            multiple.handle_multiple_ip(policy, append_list, data)
        elif policy.get('src') is not None and policy.get('dip_num') is not None:
            for dip_c in absorbdict.dip_dict:
                if policy.get('dip_num') == dip_c['dip_num']:
                    data = str(dip_c['start_ip'])
                    multiple.handle_multiple_ip(policy, append_list, data)
        elif policy.get('src') is not None:
            if policy.get('dst') is not None:
                handle_src_and_dst_nat(policy, append_list)
            else:
                for if_zone in absorbdict.if_zone_dict:
                    if policy['dst_zone'] == if_zone['zone_name']:
                        dst_if = if_zone['if_name']
                        handle_src_nat_ip_is_dst_fw(
                            policy, append_list, dst_if)
        else:
            handle_nat_if(policy, append_list)
            if not flag:
                data = str("")
                multiple.handle_multiple_ip(policy, append_list, data)


handle_src_nat_ip()
