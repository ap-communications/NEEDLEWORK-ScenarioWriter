from main import absorbdict

from main import multiple

protocol_icmp = []
protocol_tcp = []
protocol_udp = []

# protocolのリストの生成


# その他設定で用いられるプロトコルがあれば別途実装する
def handle_protocol_icmp():
    global protocol_icmp
    append_list = protocol_icmp
    for policy in absorbdict.policy_dict:
        if policy['protocol'] == '"ANY"':
            data = str("icmp")
            multiple.handle_multiple_ip(policy, append_list, data) #715
        elif policy['protocol'] == '"PING"' or policy['protocol'] == '"ICMP-ANY"':
            data = str("icmp")
            multiple.handle_multiple_ip(policy, append_list, data)#6
        else:
            data = str("icmp")
            multiple.handle_multiple_ip(policy, append_list, data)#2633


handle_protocol_icmp()


def handle_protocol_tcp():
    global protocol_tcp
    append_list = protocol_tcp
    for policy in absorbdict.policy_dict:
        if policy['protocol'] == '"ANY"':
            data = str("tcp")
            multiple.handle_multiple_ip(policy, append_list, data)#1215
        elif policy['protocol'] == '"PING"' or policy['protocol'] == '"ICMP-ANY"':
            data = str("")
            multiple.handle_multiple_ip(policy, append_list, data)#6
        else:
            data = str("tcp")
            multiple.handle_multiple_ip(policy, append_list, data)#2333


handle_protocol_tcp()


def handle_protocol_udp():
    global protocol_udp
    append_list = protocol_udp
    for policy in absorbdict.policy_dict:
        if policy['protocol'] == '"ANY"':
            data = str("udp")
            multiple.handle_multiple_ip(policy, append_list, data)#715
        elif policy['protocol'] == '"PING"' or policy['protocol'] == '"ICMP-ANY"':
            data = str("")
            multiple.handle_multiple_ip(policy, append_list, data)#6
        else:
            data = str("udp")
            multiple.handle_multiple_ip(policy, append_list, data)#2627


handle_protocol_udp()
