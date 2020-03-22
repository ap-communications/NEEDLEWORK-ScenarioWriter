from main import absorbdict
from main import multiple

dst_nat_port = []

# dst-nat-portのリストの生成


def handle_dst_nat_port():
    global dst_nat_port
    append_list = dst_nat_port
    for policy in absorbdict.policy_dict:
        if policy.get('dst_nat_port') is not None:
            for service_c in absorbdict.service_dict:
                if policy['protocol'] == '"FTP"':
                    data = str("21")
                    multiple.handle_multiple_ip(policy, append_list, data)
                elif policy['protocol'] == '"HTTP"':
                    data = str("80")
                    multiple.handle_multiple_ip(policy, append_list, data)
                elif policy['protocol'] == '"NTP"':
                    data = str("123")
                    multiple.handle_multiple_ip(policy, append_list, data)
                elif policy['protocol'] == '"DNS"':
                    data = str("53")
                    multiple.handle_multiple_ip(policy, append_list, data)
                elif service_c['service_name'] == policy['protocol']:
                    data = str(service_c['dst_port_num'].split('-')[0])
                    multiple.handle_multiple_ip(policy, append_list, data)
                else:
                    data = str("")
                    multiple.handle_multiple_ip(policy, append_list, data)
                break
        else:
            data = str("")
            multiple.handle_multiple_ip(policy, append_list, data)


handle_dst_nat_port()
