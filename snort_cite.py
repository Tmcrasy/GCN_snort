import re
import pandas as pd

msg_strings = []
ip_source_address_string = []
source_port_string = []
ip_destination_address_string = []
destination_port_string = []
msg = []

with open("alert_mykings") as f:
    lines = f.readlines()
    for line in lines:
        msg_drop = re.findall(r'].[A-Za-z1-9]+.+[A-Za-z1-9]',line)
        ip_address_port_string = re.match(r'([0-9:./-]+)\s+.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})\s+->\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})',line)
        # Classification = re.match(r'\[C.+?\]',line)   这里是添加classifition的，但考虑表标签泄露，所以这里就没有写进去，关键是代码编写也难，目前的baseline是不需要的
        # if msg or Classification:
        #     msg_strings.append(str(msg)+str(Classification))
        if msg_drop:
            msg_strings.append(msg_drop)
        if ip_address_port_string:
            ip_source_address_string.append(ip_address_port_string.group(2))
            source_port_string.append(ip_address_port_string.group(3))
            ip_destination_address_string.append(ip_address_port_string.group(4))
            destination_port_string.append(ip_address_port_string.group(5))
'''这个msg_string后期还要数据处理'''
'''列表没有split(),但是可以切片啊'''
for msg_string in msg_strings:
    if ':' not in str(msg_string):  ##当时没加str，所以，是不行，因为列表没有 not in这个操作
        msg.append(msg_string[0][2:])

# # l = ["A", "B", "C", "D"]
# msg_set = set(msg)
# f = open("sum_vocalbulary.txt", "w")
#
# for i in range(len(destination_port_string)):
#
#     # f.write(ip_destination_address_string[i] +':'+destination_port_string[i]+'\t' + ip_source_address_string[i]+':'+source_port_string[i]+'\n')
#     f.write(msg[i]+'\t')
# f.close()

f = open("alert_mykings.txt", "a")
for i in range(len(msg)):
    f.write(ip_destination_address_string[i] +':'+destination_port_string[i]+'\t' + ip_source_address_string[i]+':'+source_port_string[i]+'\n')
    # f.write(msg[i]+ ' ')
f.close()