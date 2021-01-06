from main import absorbdict
from main import multiple
src_port = []

# src-portのリストの生成


def handle_src_port():
    global src_port
    append_list = src_port
    for policy in absorbdict.policy_dict:
        for service_c in absorbdict.service_dict:
            if service_c['service_name'] == policy['protocol']:
                data = str(service_c['src_port_num'].split('-')[1])
                multiple.handle_multiple_ip(policy, append_list, data)
            else:
                data = str("")
                multiple.handle_multiple_ip(policy, append_list, data)
            break


handle_src_port()

# print('srcport : %s' % (len(src_port)))
