from main import absorbdict
from main import multiple

src_port_icmp = []
src_port_tcp = []
src_port_udp = []

# src-portのリストの生成


def handle_setting_service_name(used_protocol, service_list_c):
    flag = False
    global data_list
    for service_c in absorbdict.service_dict:
        if service_list_c == service_c['service_name']:
            flag = True
            if used_protocol == service_c['protocol_name']:
                data_list += [str(service_c['src_port_num'].split('-')[1])]
            else:
                data_list += [str("NaN")]
    else:
        if service_list_c == '"IKE-NAT"' and used_protocol == 'udp':
            data_list += [str(500)]
        elif not flag:
            print('%sの%sは送信元ポートが0-65535なので未指定で出力します' % (used_protocol, service_list_c))
            data_list += [str("")]
    return data_list


def handle_pre_service_element(policy, append_list, port_num, used_protocol):
    global data_list
    for key, value in port_num.items():
        data_list += [str("")]
    return data_list


def handle_multiple_service_port(policy, append_list, used_protocol):
    global data_list
    data_list = []
    for service_list_c in multiple.service_list:
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


def handle_src_port(append_list, used_protocol):
    for policy in absorbdict.policy_dict:
        if policy['protocol'] == '"ANY"':
            data = str("")
            multiple.handle_multiple_ip(policy, append_list, data)
        else:
            multiple.handle_service_name_list(policy, append_list, used_protocol)
            handle_multiple_service_port(policy, append_list, used_protocol)


handle_src_port(src_port_icmp, "icmp")
handle_src_port(src_port_tcp, "tcp")
handle_src_port(src_port_udp, "udp")
