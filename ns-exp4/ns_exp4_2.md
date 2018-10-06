### 网络监听 

---

**实验[2]：交换式局域⽹的⼝令嗅探** 

**实验内容简化：使用 Ettercap 实现双向 arp 欺骗 ( 降低了作业难度 )** 

、、、、、、、、、、、、、、、、、、、、、、、、、、、、、、、

**网络环境：**

- Attacker :  内网模式    IP  10.0.3.13     MAC  08:00:27:da:13:0b

- Victim :     内网模式     IP  10.0.3.15     MAC  08:00:27:9d:60:bf

- Gateway : 内网模式     IP  10.0.3.2       MAC  08:00:27:fd:31:c5

  ​		   NAT网络     IP  10.0.2.4       MAC  08:00:27:1c:f2:96

   

#### *Step 0* : 连通性测试

**Attacker ping :**

![attacker_ping](image/attacker_ping.png) 

**Victim ping :** 

![Victim_ping](image/Victim_ping.png)

**Gateway ping :**

![Gateway_ping](image/Gateway_ping.jpg)

三者及外界可以相互连通。



#### *Step 1*: ARP记录

**Attacker arp :**

![attacker_arp](image/attacker_arp.jpg)

**Victim arp :**

![Victim_arp](image/Victim_arp.png)

**Gateway arp :**

![Gateway_arp](image/Gateway_arp.png)





#### *Step 2 :* 双向 ARP欺骗

在 Attacker 命令行中输入：

> leafpad /etc/ettercap/etter.conf 

修改 ettercap 的权限，否则，后面的 hostlist 等文件会因为权限不够不能打开。

![right](image/right.png)



在 Attacker 命令行中输入：

> ettercap -G

打开 ettercap 的图形化界面。接下来就是简单的界面操作

- 点击左上角 "sniff" => 选择eth0 (10.0.3.13)
- Host => Scan for hosts，扫描当前网络中的所有主机。
- Host => Host list，扫描到的主机列表

列表如下：

![scan](image/scan.jpg)

添加目标：

![target](image/target.png)



- Mitm->ARP Poisoning，选择参数，Sniff remote connections , 开始攻击。





#### *Step 3 :* 查看毒化 ARP

**Victim arp :**

![poison_Victim](image/poison_Victim.png)

**Gateway arp :**

![poison_Gateway](image/poison_Gateway.png)

发现 受害者主机 和 网关 相互之间的 MAC 均变为 攻击者主机的 MAC。（这里就不再抓包观察了......）