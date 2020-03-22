from main import absorbdict
from main import multiple

dst_nat_ip = []


# dst-nat-ipのリストの生成
def handle_dst_nat_ip():
    global dst_nat_ip
    append_list = dst_nat_ip
    for policy in absorbdict.policy_dict:
        if policy.get('dst_nat_ip') is not None:
            for address_c in absorbdict.address_dict:
                if policy['dst_ip'] == address_c['address_name']:
                    data = str(address_c['ip_address'])
                    multiple.handle_multiple_ip(policy, append_list, data)
                    break
        elif 'MIP' in policy['dst_ip']:
            for mip_c in absorbdict.mip_dict:
                if policy['dst_ip'].strip(')"').split('(')[1] == mip_c['private_ip']:
                    data = str(mip_c['private_ip'])
                    multiple.handle_multiple_ip(policy, append_list, data)
                    break
        else:
            data = str("")
            multiple.handle_multiple_ip(policy, append_list, data)


handle_dst_nat_ip()
