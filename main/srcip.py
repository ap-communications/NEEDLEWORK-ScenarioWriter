import ipaddress

from main import absorbdict
from main import multiple

src_ip = []

# src-ipのリストの生成


# 条件によってappendするdata数が異なるため注意
def select_src_ip_from_scope_ip(policy, scope_ip):
    global src_ip
    service_name = policy['protocol']
    service_element_num = multiple.confirm_service_element(service_name)
    if policy['dst_ip'] == '"Any"' and 'Untrust"' not in policy['dst_zone']:
        try:
            src_ip += [str(scope_ip[1]), str(scope_ip[-2]),
                    str(scope_ip[-2]), str(scope_ip[1])] * service_element_num
        except IndexError:
            src_ip += [str(scope_ip[0]), str(scope_ip[0]), 'NaN', 'NaN'] * service_element_num
    elif "VIP(" in policy['dst_ip'] and policy['protocol'] == '"ANY"':
        for vip_c in absorbdict.vip_dict:
            if policy['dst_ip'].strip(')"').split('(')[1] == vip_c['if_name'] and vip_c['global_ip'] == "interface-ip":
                try:
                    src_ip += [str(scope_ip[1]), str(scope_ip[-2])
                            ] * service_element_num
                except IndexError:
                    src_ip += [str(scope_ip[0]), 'NaN'] * service_element_num
            elif policy['dst_ip'].strip(')"').split('(')[1] == vip_c['global_ip']:
                try:
                    src_ip += [str(scope_ip[1]), str(scope_ip[-2])
                            ] * service_element_num
                except IndexError:
                    src_ip += [str(scope_ip[0]), 'NaN'] * service_element_num
    else:
        address_name = policy['dst_ip']
        multiple.judge_dst_address_name(address_name)
        dst_address_element_num = multiple.dst_address_element_num
        try:
            src_ip += [str(scope_ip[1])] * service_element_num * dst_address_element_num
            src_ip += [str(scope_ip[-2])] * service_element_num * dst_address_element_num
        except IndexError:
            src_ip += [str(scope_ip[0]), 'NaN'] * service_element_num * dst_address_element_num


# 該当するIFで定義している中で最も広いnetworkアドレスを返す
def src_if_network_range(src_if):
    global route_network
    for if_ip_c in absorbdict.if_ip_dict:
        route_network = ipaddress.ip_network("2.3.4.5/32")
        if src_if.replace('"', '') == if_ip_c['if_name'] and if_ip_c['ip_address'] is not None:
            if ipaddress.IPv4Network(if_ip_c['ip_address'], strict=False).num_addresses > ipaddress.IPv4Network(route_network, strict=False).num_addresses:
                route_network = ipaddress.ip_network(
                    if_ip_c['ip_address'], strict=False)
            return route_network


# routingされている中で最も広いnetworkアドレスを返す
# TODO:route_networkがない場合に起きてる
# IFがroutingに使われていないかつIPが振られていないケースがあるか確認する
def src_if_route_network_range(policy, src_zone):
    global route_network
    confirm_src_if(policy, src_zone)
    route_network = ipaddress.ip_network("1.2.3.4/32")
    for route_c in absorbdict.route_dict:
        if src_if.replace('"', '') == route_c['if_name'].replace('"', ''):
            if ipaddress.IPv4Network(route_c['network_address']) == "0.0.0.0/0":
                continue
            elif ipaddress.IPv4Network(route_c['network_address']).num_addresses > ipaddress.IPv4Network(route_network).num_addresses:
                route_network = ipaddress.ip_network(
                    route_c['network_address'])
                return route_network
            else:
                continue
            break
    else:
        # IFにIPが振られているか確認
        for if_ip_c in absorbdict.if_ip_dict:
            if src_if.replace('"', '') == if_ip_c['if_name'] and if_ip_c.get('ip_address') is not None:
                src_if_network_range(src_if)
                break
            else:
                continue


def convert_network_address_to_scope_ip(network_address_list):
    global scope_ip
    scope_ip = ipaddress.ip_network("4.4.4.4/32")
    for item in network_address_list:
        if ipaddress.IPv4Network(item).num_addresses > ipaddress.IPv4Network(scope_ip).num_addresses:
            scope_ip = item
    return scope_ip


def define_scope_ip(policy, network_address_list):
    convert_network_address_to_scope_ip(network_address_list)
    select_src_ip_from_scope_ip(policy, scope_ip)


def get_used_fw_ip():
    global fw_ip
    fw_ip = []
    for if_ip_c in absorbdict.if_ip_dict:
        fw_ip += [ipaddress.ip_network(if_ip_c['ip_address'].split('/')[0])]
    return fw_ip


def exclude_fw_ip_from_scope_ip(scope_ip):
    global network_address_list
    network_address_list = []
    get_used_fw_ip()
    for fw_ip_c in fw_ip:
        if fw_ip_c.subnet_of(scope_ip):
            after_scope_ip = scope_ip.address_exclude(fw_ip_c)
            network_address_list += after_scope_ip
    else:
        if network_address_list == []:
            network_address_list += [scope_ip]
        else:
            pass
    return network_address_list


def add_src_ip_list_to_subnet_mask(src_ip_list):
    global exclude_ip_range_list
    exclude_ip_range_list = []
    for src_ip_list_c in src_ip_list:
        for address_c in absorbdict.address_dict:
            if src_ip_list_c == address_c['address_name'] and address_c.get('subnet_mask') is not None:
                exclude_ip_range = ipaddress.ip_network(
                    address_c['ip_address'] + '/' + address_c['subnet_mask'])
                exclude_ip_range_list += [exclude_ip_range]
                break
            elif "MIP(" in src_ip_list_c:
                for mip_c in absorbdict.mip_dict:
                    if src_ip_list_c.strip(')"').split('(')[1] == mip_c['private_ip']:
                        exclude_ip_range = ipaddress.ip_network(
                            mip_c['global_ip'] + '/' + mip_c['subnet_mask'])
                        exclude_ip_range_list += [exclude_ip_range]
                break
            elif src_ip_list_c == '"Any"':
                continue
            else:
                continue
    return exclude_ip_range_list


def exclude_src_ip_list_from_route_network(src_ip_list, route_network):
    global network_address_list
    network_address_list = []
    add_src_ip_list_to_subnet_mask(src_ip_list)
    for exclude_ip_range in exclude_ip_range_list:
        if exclude_ip_range.subnet_of(route_network) is True:
            # route_networkと同一の場合は空が追加されてしまうため注意
            after_exclude_network = route_network.address_exclude(
                exclude_ip_range)
            network_address_list += after_exclude_network
        else:
            after_exclude_network = ipaddress.ip_network(route_network)
            network_address_list += [after_exclude_network]
    convert_network_address_to_scope_ip(network_address_list)
    exclude_fw_ip_from_scope_ip(scope_ip)


# Any Any ANY の前のポリシーで使われているIPをAnyのピックアップから除外するためのリストを作る
def handle_implicit_any_ip(policy):
    global network_address_list
    src_ip_list = []
    for pre_policy in absorbdict.policy_dict:
        if policy['src_zone'] == pre_policy['src_zone'] and policy['dst_zone'] == pre_policy['dst_zone']:
            if absorbdict.group_address_dict != []:
                flag = False
                for group_address_c in absorbdict.group_address_dict:
                    if pre_policy['src_ip'] == group_address_c['group_name']:
                        flag = True
                        src_ip_list += [group_address_c['address_name']]
                        continue
                else:
                    if not flag:
                        src_ip_list += [pre_policy['src_ip']]
            elif pre_policy['src_ip'] == '"Any"':
                continue
            else:
                src_ip_list += [pre_policy['src_ip']]
            continue
        elif policy['policy_id'] == pre_policy['policy_id']:
            pass
    else:
        src_zone = policy['src_zone']
        src_if_route_network_range(policy, src_zone)
        if src_ip_list != []:
            exclude_src_ip_list_from_route_network(src_ip_list, route_network)
            define_scope_ip(policy, network_address_list)
        else:
            src_zone = policy['src_zone']
            handle_src_ip_is_any(policy, src_zone)


def dst_ip_element(policy, data, service_element_num):
    global src_ip
    if policy['dst_ip'] == '"Any"' and 'Untrust"' not in policy['dst_zone']:
        src_ip += [data] * service_element_num * 2
    elif "VIP(" in policy['dst_ip']:
        for vip_c in absorbdict.vip_dict:
            if policy['protocol'] == '"ANY"':
                if policy['dst_ip'].strip(')"').split('(')[1] == vip_c['if_name'] and vip_c['global_ip'] == "interface-ip":
                    src_ip += [data] * service_element_num
                elif policy['dst_ip'].strip(')"').split('(')[1] == vip_c['global_ip']:
                    src_ip += [data] * service_element_num
                continue
            else:
                if policy['dst_ip'].strip(')"').split('(')[1] == vip_c['if_name'] and vip_c['global_ip'] == "interface-ip" and policy['protocol'] == vip_c['service_name']:
                    src_ip += [data] * service_element_num
                    break
                elif policy['dst_ip'].strip(')"').split('(')[1] == vip_c['global_ip']:
                    src_ip += [data] * service_element_num
                    break
    else:
        address_name = policy['dst_ip']
        multiple.judge_dst_address_name(address_name)
        dst_address_element_num = multiple.dst_address_element_num
        src_ip += [data] * service_element_num * dst_address_element_num


def handle_src_ip_is_vip(policy, service_element_num):
    vip_list = []
    # ANYであればすべてのIPをvip_listに加えその要素数分だけsrc_ip_element()を行う
    # その他はvip_c['service_name']とpolicy['protocol']が一致しているIPのみ加える
    for vip_c in absorbdict.vip_dict:
        if policy['src_ip'].strip(')"').split('(')[1] == vip_c['if_name']:
            if vip_c['global_ip'] == "interface-ip" and policy['protocol'] == '"ANY"':
                vip_list += [str(vip_c['private_ip'])]
                continue
            elif vip_c['global_ip'] == "interface-ip" and vip_c['service_name'] == policy['protocol']:
                vip_list += [str(vip_c['private_ip'])]
        elif policy['src_ip'].strip(')"').split('(')[1] == vip_c['global_ip']:
            if policy['protocol'] == '"ANY"':
                vip_list += [str(vip_c['private_ip'])]
                continue
            elif vip_c['service_name'] == policy['protocol']:
                vip_list += [str(vip_c['private_ip'])]
    else:
        for i in range(len(vip_list)):
            data = vip_list[i]
            dst_ip_element(policy, data, service_element_num)


def handle_src_ip_is_any(policy, src_zone):
    confirm_src_if(policy, src_zone)
    scope_ip = ipaddress.ip_network("4.4.4.4/32")
    flag = False
    for route_c in absorbdict.route_dict:
        if src_if.replace('"', '') == route_c['if_name'].replace('"', ''):
            flag = True
            if route_c['network_address'] == "0.0.0.0/0":
                continue
            elif ipaddress.IPv4Network(route_c['network_address']).num_addresses > ipaddress.IPv4Network(scope_ip).num_addresses:
                scope_ip = ipaddress.ip_network(
                    route_c['network_address'])
                continue
    else:
        if not flag:
            flags = False
            for if_ip_c in absorbdict.if_ip_dict:
                if src_if.replace('"', '') in if_ip_c['if_name'] and if_ip_c['ip_address'] is not None:
                    flags = True
                    if ipaddress.IPv4Network(if_ip_c['ip_address'], strict=False).num_addresses > ipaddress.IPv4Network(scope_ip).num_addresses:
                        scope_ip = ipaddress.ip_network(
                            if_ip_c['ip_address'], strict=False)
                        exclude_fw_ip_from_scope_ip(scope_ip)
                        define_scope_ip(policy, network_address_list)
                        break
            else:
                if not flags:
                    exclude_fw_ip_from_scope_ip(scope_ip)
                    define_scope_ip(policy, network_address_list)
        else:
            exclude_fw_ip_from_scope_ip(scope_ip)
            define_scope_ip(policy, network_address_list)


def confirm_src_if(policy, src_zone):
    global src_if
    for if_zone in absorbdict.if_zone_dict:
        if src_zone == if_zone['zone_name']:
            src_if = if_zone['if_name']
    return src_if


def judge_src_ip_is_group_address(policy, service_element_num):
    if absorbdict.group_address_dict != []:
        flag = False
        for group_address_c in absorbdict.group_address_dict:
            if policy['src_ip'] == group_address_c['group_name']:
                flags = False
                src_address_name = group_address_c['address_name']
                for group_address2_c in absorbdict.group_address_dict:
                    if src_address_name == group_address2_c['group_name']:
                        flags = True
                        sub_address_name = group_address2_c['address_name']
                        for sub_address_c in absorbdict.address_dict:
                            if sub_address_name == sub_address_c['address_name']:
                                data = str(sub_address_c['ip_address'])
                                dst_ip_element(policy, data, service_element_num)
                else:
                    if not flags:
                        for address_c in absorbdict.address_dict:
                            if src_address_name == address_c['address_name']:
                                data = str(address_c['ip_address'])
                                dst_ip_element(policy, data, service_element_num)
                    flag = True
        else:
            if not flag:
                address_src_ip(policy, service_element_num)
    else:
        address_src_ip(policy, service_element_num)


def address_src_ip(policy, service_element_num):
    flag = False
    for address_c in absorbdict.address_dict:
        if policy['src_ip'] == address_c['address_name']:
            flag = True
            try:
                ipaddress.ip_address(address_c['ip_address'])
            except ValueError:
                data = str("NaN")
                print('policy id = %s は送信元IPがIPではないため出力されませんでした' %
                    policy['policy_id'])
                dst_ip_element(policy, data, service_element_num)
            else:
                data = str(address_c['ip_address'])
                dst_ip_element(policy, data, service_element_num)
            break
    else:
        if not flag:    
            data = str("NaN")
            print('policy id = %s は送信元IPが登録されていないため出力されませんでした' %
                    policy['policy_id'])
            dst_ip_element(policy, data, service_element_num)


def handle_mip_ip(policy, service_element_num):
    for mip_c in absorbdict.mip_dict:
        if policy['src_ip'].strip(')"').split('(')[1] == mip_c['private_ip']:
            data = str(mip_c['global_ip'])
            dst_ip_element(policy, data, service_element_num)
            break


def handle_src_ip(policy, service_element_num):
    global src_ip
    if policy.get('src_nat_ip') is not None:
        data = str(policy['src_nat_ip'])
        dst_ip_element(policy, data, service_element_num)
    elif policy['src_ip'] == '"Any"' and 'Untrust"' in policy['src_zone']:
        data = str("8.8.8.8")
        dst_ip_element(policy, data, service_element_num)
    elif policy['src_ip'] == policy['dst_ip'] == '"Any"' and policy['protocol'] == '"ANY"':
        handle_implicit_any_ip(policy)
    elif policy['src_ip'] == '"Any"':
        src_zone = policy['src_zone']
        handle_src_ip_is_any(policy, src_zone)
    elif "MIP(" in policy['src_ip']:
        handle_mip_ip(policy, service_element_num)
    elif "VIP(" in policy['src_ip']:
        handle_src_ip_is_vip(policy, service_element_num)
    else:
        judge_src_ip_is_group_address(policy, service_element_num)


def handle_multiple_element():
    for policy in absorbdict.policy_dict:
        service_name = policy['protocol']
        service_element_num = multiple.confirm_service_element(service_name)
        handle_src_ip(policy, service_element_num)


handle_multiple_element()

# print('srcip : %s' % (len(src_ip)))
