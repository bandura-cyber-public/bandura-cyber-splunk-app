import re, shlex, time
#Global File configurations

output_file = "/var/log/bandura/filtered_logs.log"
current_packet = open('/var/log/bandura/packet_received_from_tig.log', "r")
current_domain = open('/var/log/bandura/domain_received_from_tig.log', "r")

#main filtering definition to read a line, convert to key value pair, then add data to final output file.
def filter_logs(line):
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
        pass


packet_temp_line=""
domain_temp_line=""
while True:
    for line in current_packet.readlines():
        if not re.search(r'$\n',line):
            packet_temp_line += line 
        else:
            if packet_temp_line:
                filter_logs(packet_temp_line+line)
                packet_temp_line=""
            else:
                filter_logs(line)
        
    for line in current_domain.readlines():
        if not re.search(r'$\n',line):
            domain_temp_line += line 
        else:
            if domain_temp_line:
                filter_logs(domain_temp_line+line)
                domain_temp_line=""
            else:
                filter_logs(line)
    time.sleep(0.05)