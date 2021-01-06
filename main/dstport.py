from main import absorbdict
from main import multiple

dst_port_icmp = []
dst_port_tcp = []
dst_port_udp = []

src_element_num = 1
dst_element_num = 1

# dst-portのリストの生成


def handle_protocol_any(policy, append_list, used_protocol):
    if policy['src_ip'] == policy['dst_ip'] == '"Any"' and used_protocol != "icmp":
        data = str("65535")
        multiple.handle_multiple_ip(policy, append_list, data)
    else:
        if used_protocol == "icmp":
            data = str("")
        elif used_protocol == "tcp":
            data = str("80")
        elif used_protocol == "udp":
            data = str("53")
        multiple.handle_multiple_ip(policy, append_list, data)


def handle_multiple_service_port(policy, append_list, used_protocol):
    global service_list
    global data_list
    data_list = []
    service_list = multiple.service_list
    for service_list_c in service_list:
        for pre_service_name, port_num in multiple.pre_services.items():
            if service_list_c == pre_service_name:
                handle_pre_service_element(
                    policy, append_list, port_num, used_protocol)
                break
        else:
            handle_setting_service_name(used_protocol, service_list_c)
    return append_data_list_to_append_list(policy, data_list, append_list)


def handle_setting_service_name(used_protocol, service_list_c):
    flag = False
    service_protocol = []
    global data_list
    for service_c in absorbdict.service_dict:
        if service_list_c == service_c['service_name']:
            flag = True
            service_protocol.append(
                {"protocol": service_c['protocol_name'],
                 "port": service_c['dst_port_num'].split('-')[1]})
            continue
    else:
        if not flag:
            # TODO:udpの"SSH"は対応していないサービスですとなっているので調査する
            print('%sの%sは対応していないサービスです' % (used_protocol, service_list_c))
            print('出力をスキップしました')
            data_list += [str("NaN")]
        else:
            convert_service_name_to_port(
                used_protocol, service_c, service_protocol)


def convert_service_name_to_port(used_protocol, service_c, service_protocol):
    global data_list
    for service in service_protocol:
        if service['protocol'] == used_protocol:
            data_list += [str(service['port'])]
        else:
            data_list += [str("NaN")]
    return data_list


def append_data_list_to_append_list(policy, data_list, append_list):
    src_address = policy['src_ip']
    dst_address = policy['dst_ip']
    multiple.confirm_src_address_element(policy, src_address)
    multiple.confirm_dst_address_element(policy, dst_address)
    src_element_num = multiple.src_element_num
    dst_element_num = multiple.dst_element_num
    for n in range(src_element_num * dst_element_num):
        for data in data_list:
            append_list += [data]


def handle_pre_service_element(policy, append_list, port_num, used_protocol):
    global data_list
    for key, value in port_num.items():
        # valueがlistか確認する
        if type(value) is list:
            # list内のvalueをappendする
            value_num = len(value)
            if key == used_protocol:
                for value_c in value:
                    data_list += [str(value_c)]
            else:
                data_list += [str("NaN")] * value_num
        else:
            if key == used_protocol:
                data_list += [str(value)]
            else:
                data_list += [str("NaN")]
    return data_list


def handle_other_port(policy, append_list, used_protocol):
    # service_nameレベルにしたservice_listを返す
    service_name = policy['protocol']
    multiple.confirm_service_name(service_name)
    # service_list内のserviceのappend処理を行う
    handle_multiple_service_port(policy, append_list, used_protocol)


def handle_basic_dst_port(append_list, used_protocol):
    for policy in absorbdict.policy_dict:
        if policy.get('dst_nat_port') is not None:
            data = str(policy['dst_nat_port'])
            multiple.handle_multiple_ip(policy, append_list, data)
        elif policy['protocol'] == '"ANY"':
            handle_protocol_any(policy, append_list, used_protocol)
        else:
            handle_other_port(
                policy, append_list, used_protocol)


def handle_dst_port_icmp():
    global dst_port_icmp
    append_list = dst_port_icmp
    used_protocol = "icmp"
    handle_basic_dst_port(append_list, used_protocol)


def handle_dst_port_tcp():
    global dst_port_tcp
    append_list = dst_port_tcp
    used_protocol = "tcp"
    handle_basic_dst_port(append_list, used_protocol)


def handle_dst_port_udp():
    global dst_port_udp
    append_list = dst_port_udp
    used_protocol = "udp"
    handle_basic_dst_port(append_list, used_protocol)


handle_dst_port_icmp()
handle_dst_port_tcp()
handle_dst_port_udp()

# print('dst_port_icmp : %s' % (len(dst_port_icmp)))
# print('dst_port_tcp : %s' % (len(dst_port_tcp)))
# print('dst_port_udp : %s' % (len(dst_port_udp)))
