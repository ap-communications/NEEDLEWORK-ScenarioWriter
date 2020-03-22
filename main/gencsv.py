import protocol
import srcfw
import srcip
import srcnatip
import srcport
import srcvlan
import dstfw
import dstip
import dstnatip
import dstnatport
import dstport
import dstvlan
import expect
import description

from datetime import datetime
import pandas as pd

csv_title = 'SSG_convert_' + datetime.now().strftime("%Y%m%d%H%M%S") + '.csv'


def debug_info():
    print('description : %s' % (len(description.description)))
    print('dstfw : %s' % (len(dstfw.dst_fw)))
    print('dstip : %s' % (len(dstip.dst_ip)))
    print('dstnatip : %s' % (len(dstnatip.dst_nat_ip)))
    print('dstnatport : %s' % (len(dstnatport.dst_nat_port)))
    print('dst_port_icmp : %s' % (len(dstport.dst_port_icmp)))
    print('dst_port_tcp : %s' % (len(dstport.dst_port_tcp)))
    print('dst_port_udp : %s' % (len(dstport.dst_port_udp)))
    print('dstvlan : %s' % (len(dstvlan.dst_vlan)))
    print('expect : %s' % (len(expect.expect)))
    print('expect_icmp : %s' % (len(expect.expect_icmp)))
    print('protocol_icmp : %s' % (len(protocol.protocol_icmp)))
    print('protocol_tcp : %s' % (len(protocol.protocol_tcp)))
    print('protocol_udp : %s' % (len(protocol.protocol_udp)))
    print('srcfw : %s' % (len(srcfw.src_fw)))
    print('srcip : %s' % (len(srcip.src_ip)))
    print('srcnatip : %s' % (len(srcnatip.src_nat_ip)))
    print('srcport_icmp : %s' % (len(srcport.src_port_icmp)))
    print('srcport_tcp : %s' % (len(srcport.src_port_tcp)))
    print('srcport_udp : %s' % (len(srcport.src_port_udp)))
    print('srcvlan : %s' % (len(srcvlan.src_vlan)))


def generate_csv():
    # 生成した各リストをデータフレームに代入する
    df_icmp = pd.DataFrame({
        'exclude-list': '',
        '': '',
        'protocol': protocol.protocol_icmp,
        'src-fw': srcfw.src_fw,
        'src-vlan(option)': srcvlan.src_vlan,
        'src-ip': srcip.src_ip,
        'src-port(option)': srcport.src_port_icmp,
        'src-nat-ip(option)': srcnatip.src_nat_ip,
        'dst-fw': dstfw.dst_fw,
        'dst-vlan(option)': dstvlan.dst_vlan,
        'dst-nat-ip(option)': dstnatip.dst_nat_ip,
        'dst-nat-port (option)': dstnatport.dst_nat_port,
        'dst-ip': dstip.dst_ip,
        'dst-port': dstport.dst_port_icmp,
        'url/domain(option)': '',
        'anti-virus(option)': '',
        'timeout(option)': '',
        'try(option)': '',
        'expect': expect.expect_icmp,
        'description': description.description
    }).replace({'NaN': pd.np.nan, 'nan': pd.np.nan})

    df_tcp = pd.DataFrame({
        'exclude-list': '',
        '': '',
        'protocol': protocol.protocol_tcp,
        'src-fw': srcfw.src_fw,
        'src-vlan(option)': srcvlan.src_vlan,
        'src-ip': srcip.src_ip,
        'src-port(option)': srcport.src_port_tcp,
        'src-nat-ip(option)': srcnatip.src_nat_ip,
        'dst-fw': dstfw.dst_fw,
        'dst-vlan(option)': dstvlan.dst_vlan,
        'dst-nat-ip(option)': dstnatip.dst_nat_ip,
        'dst-nat-port (option)': dstnatport.dst_nat_port,
        'dst-ip': dstip.dst_ip,
        'dst-port': dstport.dst_port_tcp,
        'url/domain(option)': '',
        'anti-virus(option)': '',
        'timeout(option)': '',
        'try(option)': '',
        'expect': expect.expect,
        'description': description.description
    }).replace({'NaN': pd.np.nan, 'nan': pd.np.nan})

    df_udp = pd.DataFrame({
        'exclude-list': '',
        '': '',
        'protocol': protocol.protocol_udp,
        'src-fw': srcfw.src_fw,
        'src-vlan(option)': srcvlan.src_vlan,
        'src-ip': srcip.src_ip,
        'src-port(option)': srcport.src_port_udp,
        'src-nat-ip(option)': srcnatip.src_nat_ip,
        'dst-fw': dstfw.dst_fw,
        'dst-vlan(option)': dstvlan.dst_vlan,
        'dst-nat-ip(option)': dstnatip.dst_nat_ip,
        'dst-nat-port (option)': dstnatport.dst_nat_port,
        'dst-ip': dstip.dst_ip,
        'dst-port': dstport.dst_port_udp,
        'url/domain(option)': '',
        'anti-virus(option)': '',
        'timeout(option)': '',
        'try(option)': '',
        'expect': expect.expect,
        'description': description.description
    }).replace({'NaN': pd.np.nan, 'nan': pd.np.nan})
    # データフレームを元にcsvを生成する
    print('icmpのポリシーを生成しています')
    df_icmp.query("protocol != ''").dropna(
        how='any').to_csv(csv_title, index=False)
    print('icmpのポリシーが生成されました')
    print('tcpのポリシーを生成しています')
    df_tcp.query("protocol != ''").dropna(how='any').to_csv(
        csv_title, index=False, mode='a', header=False)
    print('tcpのポリシーが生成されました')
    print('udpのポリシーを生成しています')
    df_udp.query("protocol != ''").dropna(how='any').to_csv(
        csv_title, index=False, mode='a', header=False)
    print('udpのポリシーが生成されました')
    print('csvが生成されました')


# debug_info()
generate_csv()
