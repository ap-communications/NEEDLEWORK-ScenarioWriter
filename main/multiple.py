from main import absorbdict

# 送信元または宛先IPがAnyかつそのゾーンがUntrust以外の場合そのポリシーはリストに（Any*2）個追加する
# 送信元または宛先IPがVIPかつプロトコルがANYの場合そのポリシーはリストに（該当するVIP）個追加する
# TODO:group_addressのaddress_nameにgroup_addressは別途対応する

service_element_num = src_address_element_num = dst_address_element_num = 1

pre_services = {'"PING"': {"icmp": ''},
                '"ICMP-ANY"': {"icmp": ''},
                '"FTP"': {"tcp": '21', "udp": '21'},
                '"SSH"': {"tcp": '22'},
                '"SMTP"': {"tcp": '25'},
                '"MAIL"': {"tcp": '25'},
                '"DNS"': {"tcp": '53', "udp": '53'},
                '"HTTP"': {"tcp": '80'},
                '"POP3"': {"tcp": '110'},
                '"NTP"': {"tcp": '123', "udp": '123'},
                '"NBDS"': {"udp": '138'},
                '"IMAP"': {"tcp": '143'},
                '"SNMP"': {"tcp": '161', "udp": '161'},
                '"LDAP"': {"tcp": '389'},
                '"HTTPS"': {"tcp": '443'},
                '"SYSLOG"': {"udp": '514'},
                '"WINFRAME"': {"tcp": '1494'}}


def confirm_service_name(service_name):
    global service_list
    service_list = []
    if len(absorbdict.group_service_dict) >= 2:
        flags = False
        for group_service_c in absorbdict.group_service_dict:
            if service_name == group_service_c['group_service_name']:
                flags = True
                service_element_name = group_service_c['service_name']
                flag = False
                for group_service2_c in absorbdict.group_service_dict:
                    if service_element_name == group_service2_c['group_service_name']:
                        flag = True
                        service_list += [group_service2_c['service_name']]
                        continue
                else:
                    if not flag:
                        service_list += [service_element_name]
                continue
        else:
            if not flags:
                service_list += [service_name]
    else:
        service_list += [service_name]
    return service_list


def count_setting_service_element_num(service_list_c):
    global service_element_num
    for service_c in absorbdict.service_dict:
        if service_list_c == service_c['service_name']:
            service_element_num += 1
            continue
    return service_element_num


def count_service_element_num(service_name):
    global service_element_num
    service_element_num = 0
    confirm_service_name(service_name)
    for service_list_c in service_list:
        flag = False
        for pre_service_name, port_num in pre_services.items():
            if service_list_c == pre_service_name:
                #print(pre_service_name, service_element_num)
                flag = True
                count_pre_service_element(pre_service_name)
                service_element_num += pre_service_element_num
        else:
            if not flag:
                #print(service_list_c)
                handle_setting_service_name(service_list_c)
    return service_element_num


def confirm_service_element(service_name):
    # service_nameレベルにしたservice_listを返す
    count_service_element_num(service_name)
    # service_list内の各要素を処理しservice_element_numを返す
    return service_element_num


# TODO:検証
def handle_setting_service_name(service_list_c):
    global service_element_num
    flag = False
    for service_c in absorbdict.service_dict:
        if service_list_c == service_c['service_name']:
            flag = True
            service_element_num += 1
    else:
        if not flag:
            service_element_num += 1
    return service_element_num


def confirm_pre_service_used_protocol(pre_service_name):
    global pre_service_used_protocol
    for pre_service, port_num_dict in pre_services.items():
        if pre_service_name == pre_service:
            pre_service_used_protocol = port_num_dict
    return pre_service_used_protocol


def count_pre_service_element(pre_service_name):
    global pre_service_element_num
    confirm_pre_service_used_protocol(pre_service_name)
    used_keys = [k for k, v in pre_service_used_protocol.items()
                 ]
    pre_service_element_num = len(used_keys)
    return pre_service_element_num


def count_group_address_element(group_name):
    global address_element_num
    address_element_num = 0
    for group_address_c in absorbdict.group_address_dict:
        if group_name == group_address_c['group_name']:
            address_element_name = group_address_c['address_name']
            flag = False
            for group_address2_c in absorbdict.group_address_dict:
                if address_element_name == group_address2_c['group_name']:
                    flag = True
            else:
                if flag:
                    address_element_num = 1
                else:
                    flag = False
                    for address_c in absorbdict.address_dict:
                        if address_element_name == address_c['address_name']:
                            d = address_c
                            address_element_num += 1
                            flag = True
                    else:
                        if not flag:
                            d = group_address_c
                            address_element_num += list(
                                d.values()).count(group_name)
    else:
        return address_element_num


def judge_src_address_name(address_name):
    global src_address_element_num
    for group_address_c in absorbdict.group_address_dict:
        if group_address_c['group_name'] == address_name:
            group_name = group_address_c['group_name']
            count_group_address_element(group_name)
            src_address_element_num = address_element_num
            break
        else:
            src_address_element_num = 1
            continue
    else:
        return src_address_element_num


def judge_dst_address_name(address_name):
    global dst_address_element_num
    for group_address_c in absorbdict.group_address_dict:
        if group_address_c['group_name'] == address_name:
            group_name = group_address_c['group_name']
            count_group_address_element(group_name)
            dst_address_element_num = address_element_num
            break
        else:
            dst_address_element_num = 1
            continue
    else:
        return dst_address_element_num


def append_data_to_list(append_list, data, src_element_num, dst_element_num, service_element_num):
    append_list += [data] * src_element_num * \
        dst_element_num * service_element_num


# 各要素の要素数を判定する関数にデータを渡して戻ってきた値に応じてリストにデータを追加していく
def handle_multiple_ip(policy, append_list, data):
    global service_element_num
    src_address = policy['src_ip']
    dst_address = policy['dst_ip']
    confirm_src_address_element(policy, src_address)
    confirm_dst_address_element(policy, dst_address)
    service_name = policy['protocol']
    confirm_service_element(service_name)
    #if service_name == '"PING"' or service_name == '"ICMP-ANY"':
    #    print(service_element_num)
    append_data_to_list(append_list, data, src_element_num,
                        dst_element_num, service_element_num)


def confirm_src_vip_element(policy):
    global src_element_num
    src_element_num = 0
    for vip_c in absorbdict.vip_dict:
        if policy['src_ip'].strip(')"').split('(')[1] == vip_c['if_name']:
            if vip_c['global_ip'] == "interface-ip" and policy['protocol'] == '"ANY"':
                src_element_num += 1
                continue
            elif vip_c['global_ip'] == "interface-ip" and vip_c['service_name'] == policy['protocol']:
                src_element_num += 1
        elif policy['src_ip'].strip(')"').split('(')[1] == vip_c['global_ip']:
            if policy['protocol'] == '"ANY"':
                src_element_num += 1
                continue
            elif vip_c['service_name'] == policy['protocol']:
                src_element_num += 1
    else:
        return src_element_num


def confirm_src_address_element(policy, src_address):
    global src_element_num
    # TODO:あとで治す
    if policy['src_ip'] == '"Any"' and '"Untrust"' not in policy['src_zone']:
    #if policy['src_ip'] == '"Any"' and '"Untrust"' == policy['src_zone']:
        src_element_num = 2
    elif "VIP" in policy['src_ip'] and policy['protocol'] == '"ANY"':
        confirm_src_vip_element(policy)
    else:
        if len(absorbdict.group_address_dict) >= 2:
            address_name = src_address
            judge_src_address_name(address_name)
            src_element_num = src_address_element_num
        else:
            src_element_num = 1
    return src_element_num


def confirm_dst_vip_element(policy):
    global dst_element_num
    dst_element_num = 0
    for vip_c in absorbdict.vip_dict:
        if policy['dst_ip'].strip(')"').split('(')[1] == vip_c['if_name']:
            if vip_c['global_ip'] == "interface-ip" and policy['protocol'] == '"ANY"':
                dst_element_num += 1
                continue
            elif vip_c['global_ip'] == "interface-ip" and vip_c['service_name'] == policy['protocol']:
                dst_element_num += 1
        elif policy['dst_ip'].strip(')"').split('(')[1] == vip_c['global_ip']:
            if policy['protocol'] == '"ANY"':
                dst_element_num += 1
                continue
            elif vip_c['service_name'] == policy['protocol']:
                dst_element_num += 1
    else:
        return dst_element_num


def confirm_dst_address_element(policy, dst_address):
    global dst_element_num
    # TODO:あとで治す
    if policy['dst_ip'] == '"Any"' and '"Untrust"' not in policy['dst_zone']:
    #if policy['dst_ip'] == '"Any"' and '"Untrust"' == policy['dst_zone']:
        dst_element_num = 2
    elif "VIP" in policy['dst_ip'] and policy['protocol'] == '"ANY"':
        confirm_dst_vip_element(policy)
    else:
        if len(absorbdict.group_address_dict) >= 2:
            address_name = dst_address
            judge_dst_address_name(address_name)
            dst_element_num = dst_address_element_num
        else:
            dst_element_num = 1
    return dst_element_num
