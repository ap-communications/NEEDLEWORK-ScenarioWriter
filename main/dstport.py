from main import absorbdict
from main import multiple

dst_port_icmp = []
dst_port_tcp = []
dst_port_udp = []

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
    global data_list
    data_list = []
    service_list = multiple.service_list
    for service_list_c in service_list:
        flag = False
        for pre_service_name, port_num in multiple.pre_services.items():
            if service_list_c == pre_service_name:
                flag = True
                handle_pre_service_element(
                    policy, append_list, port_num, used_protocol)
        else:
            if not flag:
                handle_setting_service_name(used_protocol, service_list_c)
    return multiple.append_data_list_to_append_list(policy, data_list, append_list)


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
            print('%sの%sは対応していないサービスです' % (used_protocol, service_list_c))
            print('出力をスキップしました')
            data_list += [str("NaN")]
        else:
            multiple.convert_service_name_to_port(
                used_protocol, data_list, service_protocol)


def handle_pre_service_element(policy, append_list, port_num, used_protocol):
    global data_list
    for key, value in port_num.items():
        if key == used_protocol:
            data_list += [str(value)]
        else:
            data_list += [str("NaN")]
    return data_list


def handle_other_port(policy, append_list, used_protocol):
    multiple.handle_service_name_list(policy, append_list, used_protocol)
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


handle_basic_dst_port(dst_port_icmp, "icmp")
handle_basic_dst_port(dst_port_tcp, "tcp")
handle_basic_dst_port(dst_port_udp, "udp")
