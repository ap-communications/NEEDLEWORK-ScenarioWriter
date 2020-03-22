from main import absorbdict
from main import multiple

description = []

# descriptionのリストの生成


def handle_description():
    global description
    append_list = description
    for policy in absorbdict.policy_dict:
        data = str('policy id = %s' % policy['policy_id'])
        multiple.handle_multiple_ip(policy, append_list, data)


handle_description()
