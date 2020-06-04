import re
import shlex

#Global File configurations

output_file = "/var/log/bandura/filtered_logs.log"
current_packet = open('/var/log/bandura/packet_received_from_tig.log', "r", encoding="utf8", errors="ignore")
current_domain = open('/var/log/bandura/domain_received_from_tig.log', "r", encoding="utf8", errors="ignore")

#main filtering definition to read a line, convert to key value pair, then add data to final output file.
def filter_logs(lines):
    for line in lines:
        try:
            line_split = shlex.split(line)
            dict_formate = dict(token.split('=') if len(token.split('=')) == 2 else [index, token] for index, token in
                            enumerate(line_split))
            empty_string = ""
            if dict_formate.get("denied_categories") != None:
                list_keys = [2, 0, 'action', 'direction', 'country', 'as_name', 'reason', 'denied_categories', 'domain', 1,
                     'src', 'src_port', 'dst', 'dst_port']
            else:
                list_keys = [2, 0, 'action', 'direction', 'country', 'as_name', 'reason', 'matched_categories', 'domain', 1,
                     'src', 'src_port', 'dst', 'dst_port']
            for i in list_keys:
                empty_string += '"{0}",'.format(dict_formate.get(i,"#:#").strip(":,"))

            f = open(output_file, 'a')
            f.write(empty_string.strip(",")+'\n')
            f.close()
        except Exception as e:
            print(e)
            print(line)
            continue



#Packet and Domainlogs buffer to listen until 100 logs count is reached and send them for filtering at one, instead of realtime.
domain_count, packet_count = 0, 0
packet_buffer, domain_buffer = [], []
while True:
    for line in current_packet:
        packet_buffer.append(line)
        packet_count += 1
        if packet_count == 100:
            filter_logs(packet_buffer)
            packet_count = 0
            packet_buffer.clear()

    for line in current_domain:
        domain_buffer.append(line)
        domain_count += 1
        if domain_count == 100:
            filter_logs(domain_buffer)
            domain_count = 0
            domain_buffer.clear()
