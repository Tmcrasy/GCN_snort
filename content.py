a = []
with open('./sum_vocalbulary.txt') as f:
    data = f.read().replace('(','')
    print(type(data))
    # print(data)
    a = data.split(' ')
    # print(set(a))
    print(len(set(a)))
import re
    ##总的表是拿到了，但是呢，标签构建，然后就是tf-idf的构建。
# with open('/Users/lianghuaxiong/Downloads/GCN/gcn_snort_dataset/引用表/alert_mykings.txt') as f:
#     data_alert = f.read().replace('(','')
#     b = data.split('')
msg = []
msg_strings = []
ip_source_address_string = []
source_port_string = []
ip_destination_address_string = []
destination_port_string = []

with open("alert_web") as f:
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
print(type(msg))  #msg是list
# num = []
for k,strs in enumerate(msg):
    b = strs.split(',')
    # print(b)  #b是一句话，是一个list
    # print(type(b))      # list
    # print(len(b))     #1
    # b = str(b)
    # b = b.split()
    # print(b)
    for strs_b in b:
        print('!!!!!')  
        print(strs_b)  #一句话
        # print(type(strs_b))  # str
        c = strs_b.split()
        # print(c)
        print('!!!!!')
        num = [0 for i in range(0,len(set(a)))] 
        for c_str in c:        #可以把这段代码拆开了
            for i,x in enumerate(set(a)):
                if c_str == x:
                    num[i] = 1
                    ##写进去文件
        with open('alert_web.txt','a') as f:
            # f.write(str(num).replace('[','').replace(',','\t'))

            kk =str(num).replace('[','').replace(']','')
            mm = kk.replace(',','\t')
            # f.write(ip_destination_address_string[k])
            f.write(ip_source_address_string[k])
            f.write(':')
            # f.write(destination_port_string[k])
            f.write(source_port_string[k])
            f.write('\t')
            f.write(mm)
            f.write('\t')
            f.write('alert_web')
            f.write('\n')

#有三个地方要改的，一个是读取文件名，另外一个也是写文件名，还有一个即使标签，label

 ##数目不对，自己明天调试下
# print(msg[0])
# print(type(msg[0]))
# print(num)
# print(len(num))

