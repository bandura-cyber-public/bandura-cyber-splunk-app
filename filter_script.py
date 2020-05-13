import re

output_file = "/var/log/bandura/filtered_logs.log"
current_packet = open('/var/log/bandura/packet_received_from_tig.log', "r", encoding="utf8", errors="ignore")
current_domain = open('/var/log/bandura/domain_received_from_tig.log', "r", encoding="utf8", errors="ignore")

def filter_domian_logs(lines):
    reg_exp_domain = ['(\d{4}.*?\d\s)', 'action=(.*?),', 'direction=(.*?),', 'country=(.*?)",', 'as_name=(.*?),',
                      'reason=(.*?),\s']

    for i in lines:
        try:
            if re.search("denied_categories=(.*?\"),", i):
                var = re.search("denied_categories=(.*?\"),", i).group(1)+',"'+str(re.search('domain=(.*?)(\\n|\s)',i).group(1))+'",'+str(re.search('\s(.*?)\s',i).group(1).replace(' ','"'))
            elif re.search("matched_categories=(.*?\"),",i):
                var = re.search("matched_categories=(.*?\"),", i).group(1)+',"'+str(re.search('domain=(.*?)(\\n|\s)',i).group(1))+','+str(re.search('\s(.*?)\s',i).group(1).replace(' ','"'))
            else:
                var = '"#:#"'+',"'+str(re.search('domain=(.*?)(\\n|\s)',i).group(1))+'",'
                var = var+str(re.search('\s(.*?)\s',i).group(1).replace(' ','"'))
        except Exception:
            print("---Error in---")
            print(i)
            continue
        if re.search("(\d{4}.*?\d\s)", i) and  re.search("action=(.*?),", i) and re.search("direction=(.*?),", i):
            f = open(output_file, 'a')
            f.write('\"domain\",' + ','.join(
                ['"' + re.search(a, i).group(1).strip(', "') + '"' if re.search(a, i) else '"' + "#:#" + '"' for a in
                 reg_exp_domain]) +','+var+"\n")
            f.close()



def filter_packet_logs(lines):
    reg_exp = ['(\d{4}.*?\d\s)', 'action=(.*?),', 'direction=(.*?),', 'country="(.*?)",', 'as_name=(.*?"),',
               'reason=(.*?),\s']

    for i in lines:
        try:
            if re.search("denied_categories=(.*?\"),", i):
                var = re.search("denied_categories=(.*?\"),", i).group(1)+',"#:#",'+str(re.search('\s(.*?)\s',i).group(1).replace(' ','"'))
            elif re.search("matched_categories=(.*?\"),",i):
                var=re.search("matched_categories=(.*?\"),", i).group(1)+',"#:#",'+str(re.search('\s(.*?)\s',i).group(1).replace(' ','"'))
            else:
                var = '"#:#"'+',"#:#",'+str(re.search('\s(.*?)\s',i).group(1).replace(' ','"'))
        except Exception:
            print("---Error in---")
            print(i)
            continue
        if re.search("(\d{4}.*?\d\s)", i) and  re.search("action=(.*?),", i) and re.search("direction=(.*?),", i) and re.search('country="(.*?)",', i)  and re.search('as_name=(.*?"),', i) :
            f = open(output_file, 'a')
            f.write('\"packet\",' + ','.join(
                ['"' + re.search(a, i).group(1).strip(', "') + '"' if re.search(a, i) else '"' + "#:#" + '"' for a in
                 reg_exp]) +','+var+ "\n")
            f.close()


domain_count, packet_count = 0, 0
packet_buffer, domain_buffer = [], []
while True:
    for line in current_packet:
        packet_buffer.append(line)
        packet_count += 1
        if packet_count == 100:
            filter_packet_logs(packet_buffer)
            packet_count = 0
            packet_buffer.clear()

    for line in current_domain:
        domain_buffer.append(line)
        domain_count += 1
        if domain_count == 100:
            filter_domian_logs(domain_buffer)
            domain_count = 0
            domain_buffer.clear()
