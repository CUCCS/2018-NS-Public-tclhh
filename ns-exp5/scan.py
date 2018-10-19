from scapy.all import * 

dst_ip = '10.0.3.2'
dst_port_tcp = [21,56,80]
dst_port_udp = [21,56]
xmas_icmp_code = [1,2,3,9,10,13]
udp_icmp_code = [1,2,9,10,13]

def tcp_connect_scan(dst,dports = dst_port_tcp,flag = "S",time = 5):
	#
	ans,unans = sr(IP(dst = dst_ip)/TCP(dport = dports,flags = flag),timeout = time) 
	print "=================================================="
	print 'response flags:'
	ans.nsummary(lambda (s,r):r.sprintf("%TCP.sport%\t%TCP.flags%"))
	print "=================================================="
	print "port status:"
	ans.summary(lfilter = lambda (s,r):r.sprintf("%TCP.flags%") == "SA",prn = lambda (r,s):s.sprintf("%TCP.sport%\tOpen"))
	ans.summary(lfilter = lambda (s,r):r.sprintf("%TCP.flags%") == "RA",prn = lambda (r,s):s.sprintf("%TCP.sport%\tClosed"))
	unans.summary(lambda s:s.sprintf("%TCP.dport%\tFiltered"))
	print "=================================================="

	for resp_src,resp_dst in ans:
		if(resp_dst.getlayer(TCP).flags & 2):
			print "port " + str(resp_dst.sport)
			send(IP(dst = dst_ip)/TCP(dport = resp_dst.sport,flags = "RA"))

def tcp_stealth_scan(dst,dports = dst_port_tcp,flag = "S",time = 5):

	ans,unans = sr(IP(dst = dst_ip)/TCP(dport = dports,flags = flag),timeout = time) 
	print "=================================================="
	print 'response flags:'
	ans.nsummary(lambda (s,r):r.sprintf("%TCP.sport%\t%TCP.flags%"))
	print "=================================================="
	print "port status:"
	ans.summary(lfilter = lambda (s,r):r.sprintf("%TCP.flags%") == "SA",prn = lambda (r,s):s.sprintf("%TCP.sport%\tOpen"))
	ans.summary(lfilter = lambda (s,r):r.sprintf("%TCP.flags%") == "RA",prn = lambda (r,s):s.sprintf("%TCP.sport%\tClosed"))
	unans.summary(lambda s:s.sprintf("%TCP.dport%\tFiltered"))
	print "=================================================="

	
	for resp_src,resp_dst in ans:
		if(resp_dst.getlayer(TCP).flags & 2):
			print "port " + str(resp_dst.sport)
			send(IP(dst = dst_ip)/TCP(dport = resp_dst.sport,flags = "R"))


def tcp_xmas_scan(dst,dports = dst_port_tcp,flag = "FPU",time = 5):

	ans,unans = sr(IP(dst = dst_ip)/TCP(dport = dports,flags = flag),timeout = time)
	print "=================================================="
	print 'response status:'
	ans.summary(lfilter = lambda (s,r):not r.haslayer(ICMP),prn = lambda (s,r):r.sprintf("port:%TCP.sport%\tflags:%TCP.flags%"))
	ans.summary(lfilter = lambda (s,r):not r.haslayer(TCP),prn = lambda (s,r):r.sprintf("type:%ICMP.type%\tcode:%ICMP.code%"))
	print "=================================================="
	print "port status:"
	unans.summary(lambda s:s.sprintf("%TCP.dport%\tOpen|Filtered"))
	ans.summary(lfilter = lambda (s,r):r.sprintf("%TCP.flags%") == "RA",prn = lambda (r,s):s.sprintf("%TCP.sport%\tClosed"))
	ans.summary(lfilter = lambda (s,r):r.haslayer(ICMP) and (r.getlayer(ICMP).code == 3 and r.getlayer(ICMP).code in xmas_icmp_code),prn = lambda (r,s):r.sprintf("%TCP.dport%\tFiltered"))
	print "=================================================="
	
def udp_scan(dst,dports = dst_port_udp,time = 3):
	
	ans,unans = sr(IP(dst = dst_ip)/UDP(dport = dports))
	print "=================================================="
	print 'response status:'
	ans.summary(lfilter = lambda (s,r):not r.haslayer(ICMP),prn = lambda (s,r):r.sprintf("port:%UDP.sport%"))
	ans.summary(lfilter = lambda (s,r):not r.haslayer(UDP),prn = lambda (s,r):r.sprintf("type:%ICMP.type%\tcode:%ICMP.code%"))
	print "=================================================="
	print "port status:"
	ans.summary(lfilter = lambda (s,r):(not r.haslayer(ICMP)) and r.haslayer(UDP),prn = lambda (s,r):r.sprintf("%UDP.sport%\tOpen"))
	ans.summary(lfilter = lambda (s,r):r.haslayer(ICMP) and (r.getlayer(ICMP).type == 3 and r.getlayer(ICMP).code == 3),prn = lambda (s,r):s.sprintf("%UDP.dport%\tClosed"))
	ans.summary(lfilter = lambda (s,r):r.haslayer(ICMP) and (r.getlayer(ICMP).type == 3 and r.getlayer(ICMP).code in udp_icmp_code),prn = lambda (s,r):s.sprintf("%UDP.dport%\tFiltered"))
	unans.summary(lambda s:s.sprintf("%TCP.dport%\tOpen|Filtered"))


if __name__ == '__main__':
	print "TCP_connect_scan:"
	tcp_connect_scan(dst_ip,dst_port_tcp)
	print "TCP_stealth_scan:"
	tcp_stealth_scan(dst_ip,dst_port_tcp)
	print "TCP_xmas_scan:"
	tcp_xmas_scan(dst_ip,dst_port_tcp)
	print "UDP_scan:"
	udp_scan(dst_ip,dst_port_tcp)



