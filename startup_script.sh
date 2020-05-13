mv /var/log/bandura/packet_received_from_tig.log /var/log/bandura/packet_received_from_tig.log.BAK ;
mv /var/log/bandura/domain_received_from_tig.log /var/log/bandura/domain_received_from_tig.log.BAK ;
mv /var/log/bandura/filtered_logs.log /var/log/bandura/filtered_logs.log.BAK ;
touch /var/log/bandura/packet_received_from_tig.log ;
touch /var/log/bandura/domain_received_from_tig.log ;
touch /var/log/bandura/filtered_logs.log ;
/opt/splunk/bin/./splunk start ;
python3 /var/log/bandura/onreboot.py ;
