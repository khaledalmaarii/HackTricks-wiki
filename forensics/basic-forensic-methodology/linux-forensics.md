# 리눅스 포렌식

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급 커뮤니티 도구**를 활용한 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 자신의 해킹 기법을 공유하세요.

</details>

## 초기 정보 수집

### 기본 정보

먼저, **USB**에 **잘 알려진 이진 파일과 라이브러리**가 있는 것이 좋습니다(우분투를 가져와서 _/bin_, _/sbin_, _/lib,_ 및 _/lib64_ 폴더를 복사할 수 있습니다). 그런 다음 USB를 마운트하고 환경 변수를 수정하여 해당 이진 파일을 사용할 수 있습니다:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
시스템이 좋고 알려진 이진 파일을 사용하도록 구성되었다면 **기본 정보를 추출**할 수 있습니다:
```bash
date #Date and time (Clock may be skewed, Might be at a different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuous mode?)
ps -ef #Running processes
netstat -anp #Proccess and ports
lsof -V #Open files
netstat -rn; route #Routing table
df; mount #Free space and mounted devices
free #Meam and swap space
w #Who is connected
last -Faiwx #Logins
lsmod #What is loaded
cat /etc/passwd #Unexpected data?
cat /etc/shadow #Unexpected data?
find /directory -type f -mtime -1 -print #Find modified files during the last minute in the directory
```
#### 수상한 정보

기본 정보를 얻을 때 다음과 같은 이상한 점을 확인해야 합니다:

* **루트 프로세스**는 일반적으로 낮은 PID로 실행되므로, 큰 PID를 가진 루트 프로세스를 발견하면 의심할 수 있습니다.
* `/etc/passwd` 내에 쉘이 없는 사용자의 **등록된 로그인**을 확인하세요.
* 쉘이 없는 사용자의 **비밀번호 해시**를 `/etc/shadow`에서 확인하세요.

### 메모리 덤프

실행 중인 시스템의 메모리를 얻기 위해 [**LiME**](https://github.com/504ensicsLabs/LiME)를 사용하는 것이 좋습니다.\
**컴파일**하기 위해서는 피해자의 머신이 사용하는 **동일한 커널**을 사용해야 합니다.

{% hint style="info" %}
피해자의 머신에는 LiME나 다른 것을 **설치할 수 없다는 것**을 기억하세요. 이는 여러 변경 사항을 만들기 때문입니다.
{% endhint %}

따라서, 동일한 버전의 Ubuntu를 가지고 있다면 `apt-get install lime-forensics-dkms`를 사용할 수 있습니다.\
다른 경우에는 [**LiME**](https://github.com/504ensicsLabs/LiME)를 github에서 다운로드하고 올바른 커널 헤더와 함께 컴파일해야 합니다. 피해자 머신의 **정확한 커널 헤더**를 얻기 위해 `/lib/modules/<kernel version>` 디렉토리를 복사한 다음, 해당 디렉토리를 사용하여 LiME를 **컴파일**할 수 있습니다:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME는 3가지 형식을 지원합니다:

* Raw (모든 세그먼트를 연결한 형태)
* Padded (raw와 동일하지만 오른쪽 비트에는 0이 들어갑니다)
* Lime (메타데이터와 함께 권장되는 형식)

LiME는 덤프를 시스템에 저장하는 대신 `path=tcp:4444`와 같은 방법을 사용하여 네트워크를 통해 덤프를 전송하는 데에도 사용될 수 있습니다.

### 디스크 이미징

#### 시스템 종료

먼저, 시스템을 종료해야 합니다. 회사가 종료할 수 없는 프로덕션 서버인 경우에는 항상 이 옵션이 가능하지 않을 수 있습니다.\
시스템을 종료하는 두 가지 방법이 있습니다. **일반 종료**와 **"전원을 뽑는" 종료**입니다. 첫 번째 방법은 **프로세스가 정상적으로 종료**되고 **파일 시스템이 동기화**되는 것을 허용하지만, **악성 코드**가 **증거를 파괴**할 수도 있습니다. "전원을 뽑는" 방법은 **일부 정보 손실**을 야기할 수 있습니다 (메모리 이미지를 이미 가져왔으므로 정보의 대부분이 손실되지 않을 것입니다) 그리고 **악성 코드는 아무런 조치를 취할 수 없습니다**. 따라서, **악성 코드**가 있을 수 있다고 의심되면 시스템에서 **`sync`** **명령어**를 실행한 후 전원을 뽑으세요.

#### 디스크 이미지 캡처

사건과 관련된 어떤 것이든 컴퓨터를 연결하기 전에, 정보를 수정하지 않도록 **읽기 전용으로 마운트**되는지 확인해야 합니다.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### 디스크 이미지 사전 분석

더 이상의 데이터가 없는 디스크 이미지를 이미징합니다.
```bash
#Find out if it's a disk image using "file" command
file disk.img
disk.img: Linux rev 1.0 ext4 filesystem data, UUID=59e7a736-9c90-4fab-ae35-1d6a28e5de27 (extents) (64bit) (large files) (huge files)

#Check which type of disk image it's
img_stat -t evidence.img
raw
#You can list supported types with
img_stat -i list
Supported image format types:
raw (Single or split raw file (dd))
aff (Advanced Forensic Format)
afd (AFF Multiple File)
afm (AFF with external metadata)
afflib (All AFFLIB image formats (including beta ones))
ewf (Expert Witness Format (EnCase))

#Data of the image
fsstat -i raw -f ext4 disk.img
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 162850f203fd75afab4f1e4736a7e776

Last Written at: 2020-02-06 06:22:48 (UTC)
Last Checked at: 2020-02-06 06:15:09 (UTC)

Last Mounted at: 2020-02-06 06:15:18 (UTC)
Unmounted properly
Last mounted on: /mnt/disk0

Source OS: Linux
[...]

#ls inside the image
fls -i raw -f ext4 disk.img
d/d 11: lost+found
d/d 12: Documents
d/d 8193:       folder1
d/d 8194:       folder2
V/V 65537:      $OrphanFiles

#ls inside folder
fls -i raw -f ext4 disk.img 12
r/r 16: secret.txt

#cat file inside image
icat -i raw -f ext4 disk.img 16
ThisisTheMasterSecret
```
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)을 사용하여 세계에서 가장 **고급**한 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축**하고 자동화하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 알려진 악성 코드 검색

### 수정된 시스템 파일

리눅스는 시스템 구성 요소의 무결성을 확인하는 도구를 제공하여 잠재적으로 문제가 될 수 있는 파일을 식별하는 데 도움이 됩니다.

- **RedHat 기반 시스템**: `rpm -Va`를 사용하여 포괄적인 검사를 수행합니다.
- **Debian 기반 시스템**: 초기 검증을 위해 `dpkg --verify`를 사용하고, `debsums`를 `apt-get install debsums`로 설치한 후 `debsums | grep -v "OK$"`를 사용하여 문제를 식별합니다.

### 악성 코드/루트킷 탐지 도구

다음 페이지를 읽어 악성 코드를 찾는 데 유용한 도구에 대해 알아보세요:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## 설치된 프로그램 검색

Debian 및 RedHat 시스템에서 설치된 프로그램을 효과적으로 검색하려면 일반적인 디렉토리에서 수동 검사와 함께 시스템 로그 및 데이터베이스를 활용해야 합니다.

- Debian의 경우, 패키지 설치에 대한 세부 정보를 가져오기 위해 **_`/var/lib/dpkg/status`_** 및 **_`/var/log/dpkg.log`_**를 검사하고, 특정 정보를 필터링하기 위해 `grep`을 사용합니다.

- RedHat 사용자는 `rpm -qa --root=/mntpath/var/lib/rpm`을 사용하여 RPM 데이터베이스를 쿼리하여 설치된 패키지를 나열할 수 있습니다.

이러한 패키지 관리자 외부에서 수동으로 또는 이외에 설치된 소프트웨어를 찾으려면 **_`/usr/local`_**, **_`/opt`_**, **_`/usr/sbin`_**, **_`/usr/bin`_**, **_`/bin`_**, **_`/sbin`_**과 같은 디렉토리를 탐색하세요. 디렉토리 목록을 시스템별 명령어와 결합하여 알려진 패키지와 관련이 없는 실행 파일을 식별하여 모든 설치된 프로그램을 검색하는 데 도움을 얻을 수 있습니다.
```bash
# Debian package and log details
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
# RedHat RPM database query
rpm -qa --root=/mntpath/var/lib/rpm
# Listing directories for manual installations
ls /usr/sbin /usr/bin /bin /sbin
# Identifying non-package executables (Debian)
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
# Identifying non-package executables (RedHat)
find /sbin/ –exec rpm -qf {} \; | grep "is not"
# Find exacuable files
find / -type f -executable | grep <something>
```
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급** 커뮤니티 도구로 구동되는 **워크플로우**를 쉽게 구축하고 자동화할 수 있습니다.\
오늘 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 삭제된 실행 중인 이진 파일 복구

/tmp/exec에서 실행되고 삭제된 프로세스를 상상해보십시오. 추출할 수 있습니다.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## 자동 시작 위치 검사

### 예약된 작업
```bash
cat /var/spool/cron/crontabs/*  \
/var/spool/cron/atjobs \
/var/spool/anacron \
/etc/cron* \
/etc/at* \
/etc/anacrontab \
/etc/incron.d/* \
/var/spool/incron/* \

#MacOS
ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/
```
### 서비스

악성 소프트웨어가 서비스로 설치될 수 있는 경로:

- **/etc/inittab**: rc.sysinit과 같은 초기화 스크립트를 호출하여 시작 스크립트로 이어집니다.
- **/etc/rc.d/** 및 **/etc/rc.boot/**: 서비스 시작을 위한 스크립트를 포함하며, 후자는 이전 버전의 Linux에서 찾을 수 있습니다.
- **/etc/init.d/**: Debian과 같은 특정 Linux 버전에서 시작 스크립트를 저장하는 데 사용됩니다.
- 서비스는 Linux 변형에 따라 **/etc/inetd.conf** 또는 **/etc/xinetd/**를 통해 활성화될 수도 있습니다.
- **/etc/systemd/system**: 시스템 및 서비스 관리자 스크립트를 위한 디렉토리입니다.
- **/etc/systemd/system/multi-user.target.wants/**: 다중 사용자 런레벨에서 시작되어야 하는 서비스에 대한 링크를 포함합니다.
- **/usr/local/etc/rc.d/**: 사용자 정의 또는 타사 서비스를 위한 디렉토리입니다.
- **~/.config/autostart/**: 사용자별 자동 시작 응용 프로그램을 위한 디렉토리로, 사용자를 대상으로 한 악성 소프트웨어의 은닉 장소가 될 수 있습니다.
- **/lib/systemd/system/**: 설치된 패키지에서 제공하는 시스템 전역 기본 유닛 파일입니다.


### 커널 모듈

악성 소프트웨어가 루트킷 구성 요소로서 자주 사용하는 Linux 커널 모듈은 시스템 부팅 시 로드됩니다. 이러한 모듈에 대한 중요한 디렉토리와 파일은 다음과 같습니다:

- **/lib/modules/$(uname -r)**: 실행 중인 커널 버전의 모듈을 보관합니다.
- **/etc/modprobe.d**: 모듈 로딩을 제어하는 구성 파일을 포함합니다.
- **/etc/modprobe** 및 **/etc/modprobe.conf**: 전역 모듈 설정을 위한 파일입니다.

### 기타 자동 시작 위치

Linux는 사용자 로그인 시 자동으로 프로그램을 실행하기 위해 다양한 파일을 사용하며, 이는 잠재적으로 악성 소프트웨어를 숨길 수 있습니다:

- **/etc/profile.d/***, **/etc/profile**, 및 **/etc/bash.bashrc**: 모든 사용자 로그인에 실행됩니다.
- **~/.bashrc**, **~/.bash_profile**, **~/.profile**, 및 **~/.config/autostart**: 사용자별로 로그인 시 실행되는 파일입니다.
- **/etc/rc.local**: 모든 시스템 서비스가 시작된 후 실행되며, 다중 사용자 환경으로의 전환을 나타냅니다.

## 로그 검사

Linux 시스템은 다양한 로그 파일을 통해 사용자 활동 및 시스템 이벤트를 추적합니다. 이러한 로그는 무단 접근, 악성 소프트웨어 감염 및 기타 보안 사고를 식별하는 데 중요합니다. 주요 로그 파일은 다음과 같습니다:

- **/var/log/syslog** (Debian) 또는 **/var/log/messages** (RedHat): 시스템 전체의 메시지와 활동을 기록합니다.
- **/var/log/auth.log** (Debian) 또는 **/var/log/secure** (RedHat): 인증 시도, 성공 및 실패한 로그인을 기록합니다.
- `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` 명령을 사용하여 관련 인증 이벤트를 필터링할 수 있습니다.
- **/var/log/boot.log**: 시스템 시작 메시지를 포함합니다.
- **/var/log/maillog** 또는 **/var/log/mail.log**: 이메일 서버 활동을 기록하며, 이메일 관련 서비스를 추적하는 데 유용합니다.
- **/var/log/kern.log**: 오류 및 경고를 포함한 커널 메시지를 저장합니다.
- **/var/log/dmesg**: 장치 드라이버 메시지를 보관합니다.
- **/var/log/faillog**: 로그인 실패 시도를 기록하여 보안 침해 조사에 도움을 줍니다.
- **/var/log/cron**: cron 작업 실행을 기록합니다.
- **/var/log/daemon.log**: 백그라운드 서비스 활동을 추적합니다.
- **/var/log/btmp**: 로그인 실패 시도를 기록합니다.
- **/var/log/httpd/**: Apache HTTPD 오류 및 액세스 로그를 포함합니다.
- **/var/log/mysqld.log** 또는 **/var/log/mysql.log**: MySQL 데이터베이스 활동을 기록합니다.
- **/var/log/xferlog**: FTP 파일 전송을 기록합니다.
- **/var/log/**: 여기에서 예기치 않은 로그를 항상 확인하세요.

{% hint style="info" %}
Linux 시스템 로그 및 감사 하위 시스템은 침입 또는 악성 소프트웨어 사건에서 비활성화되거나 삭제될 수 있습니다. Linux 시스템의 로그는 일반적으로 악성 활동에 대한 가장 유용한 정보를 포함하므로 침입자들은 이를 정기적으로 삭제합니다. 따라서 사용 가능한 로그 파일을 검사할 때 삭제 또는 조작의 표시일 수 있는 간격이나 순서가 있는지 확인하는 것이 중요합니다.
{% endhint %}

**Linux는 각 사용자의 명령 기록을 유지**하며, 다음 위치에 저장됩니다:

- ~/.bash_history
- ~/.zsh_history
- ~/.zsh_sessions/*
- ~/.python_history
- ~/.*_history

또한, `last -Faiwx` 명령은 사용자 로그인 목록을 제공합니다. 알 수 없거나 예상치 못한 로그인을 확인하세요.

추가 권한을 부여할 수 있는 파일을 확인하세요:

- 부여되었을 수 있는 예기치 않은 사용자 권한을 확인하기 위해 `/etc/sudoers`를 검토하세요.
- 부여되었을 수 있는 예기치 않은 사용자 권한을 확인하기 위해 `/etc/sudoers.d/`를 검토하세요.
- 이상한 그룹 멤버십이나 권한을 식별하기 위해 `/etc/groups`를 검토하세요.
- 이상한 그룹 멤버십이나 권한을 식별하기 위해 `/etc/passwd`를 검토하세요.

일부 애플리케이션은 자체 로그를 생성하기도 합니다:

- **SSH**: 무단 원격 연결을 나타낼 수 있는 _~/.ssh/authorized_keys_ 및 _~/.ssh/known_hosts_를 검토하세요.
- **Gnome 데스크톱**: Gnome 애플리케이션을 통해 최근에 액세스한 파일을 나타내는 _~/.recently-used.xbel_을 확인하세요.
- **Firefox/Chrome**: 수상한 활동을 나타내는 브라우저 기록 및 다운로드를 _~/.mozilla/firefox_ 또는 _~/.config/google-chrome_에서 확인하세요.
- **VIM**: 액세스한 파일 경로 및 검색 기록과 같은 사용 세부 정보를 포함하는 _~/.viminfo_를 검토하세요.
- **Open Office**: 침해된 파일을 나타낼 수 있는 최근 문서 액세스를 확인하세요.
- **FTP/SFTP**: 무단 파일 전송을 나타낼 수 있는 _~/.ftp_history_ 또는 _~/.sftp_history_ 로그를 검토하세요.
- **MySQL**: 무단 데이터베이스 활동을 나타낼 수 있는 실행된 MySQL 쿼리를 포함하는 _~/.mysql_history_를 조사하세요.
- **Less**: 보여진 파일 및 실행된 명령과 같은 사용 기록을 포함하는 _~/.lesshst_를 분석하세요.
- **Git**: 저장소 변경 사항을 확인하기 위해 _~/.gitconfig_ 및 프로젝트 _.git/logs_를 검토하세요.

### USB 로그

[**usbrip**](https://github.com/snovvcrash/usbrip)은 Linux 로그 파일(`/var/log/syslog*` 또는 `/var/log/messages*` - 배포판에 따라 다름)을 파싱하여 USB 이벤트 기록 테이블을 작성하는 순수 Python 3로 작성된 소프트웨어입니다.

**사용된 모든 USB를 알 수 있는 것은 흥미로울 것**이며, USB 목록을 포함한 "위반 이벤트"(해당 목록에 없는 USB 사용)를 찾기 위해 허가된 USB 목록이 있는 경우 더욱 유용할 것입니다.

### 설치
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### 예시

#### Example 1: Collecting System Information

#### 예시 1: 시스템 정보 수집

To begin a Linux forensic investigation, it is important to collect relevant system information. This includes details such as the operating system version, kernel version, installed packages, running processes, network configuration, and user accounts.

리눅스 포렌식 조사를 시작하기 위해서는 관련된 시스템 정보를 수집하는 것이 중요합니다. 이에는 운영 체제 버전, 커널 버전, 설치된 패키지, 실행 중인 프로세스, 네트워크 구성 및 사용자 계정과 같은 세부 정보가 포함됩니다.

To collect this information, you can use various commands such as `uname`, `lsb_release`, `dpkg`, `rpm`, `ps`, `netstat`, and `cat /etc/passwd`. These commands will provide you with the necessary details about the system.

이 정보를 수집하기 위해 `uname`, `lsb_release`, `dpkg`, `rpm`, `ps`, `netstat` 및 `cat /etc/passwd`와 같은 다양한 명령을 사용할 수 있습니다. 이러한 명령은 시스템에 대한 필요한 세부 정보를 제공해줍니다.

#### Example 2: Analyzing Log Files

#### 예시 2: 로그 파일 분석

Log files are a valuable source of information in a forensic investigation. They can provide insights into system activities, user actions, and potential security incidents.

로그 파일은 포렌식 조사에서 중요한 정보의 원천입니다. 시스템 활동, 사용자 작업 및 잠재적인 보안 사건에 대한 통찰력을 제공할 수 있습니다.

To analyze log files, you can use tools such as `grep`, `awk`, and `sed`. These tools allow you to search for specific keywords, filter out irrelevant information, and extract relevant data for further analysis.

로그 파일을 분석하기 위해 `grep`, `awk`, `sed`와 같은 도구를 사용할 수 있습니다. 이러한 도구를 사용하면 특정 키워드를 검색하고 관련 없는 정보를 걸러내며 추가 분석을 위해 관련 데이터를 추출할 수 있습니다.

For example, you can use the command `grep "error" /var/log/syslog` to search for any error messages in the syslog file. This can help identify potential issues or security breaches.

예를 들어, `grep "error" /var/log/syslog` 명령을 사용하여 syslog 파일에서 오류 메시지를 검색할 수 있습니다. 이를 통해 잠재적인 문제 또는 보안 위반 사항을 식별할 수 있습니다.

#### Example 3: Recovering Deleted Files

#### 예시 3: 삭제된 파일 복구

In some cases, it may be necessary to recover deleted files as part of a forensic investigation. When a file is deleted, it is not immediately removed from the system. Instead, the file's metadata is modified to indicate that the space it occupies is available for reuse.

일부 경우에는 포렌식 조사의 일환으로 삭제된 파일을 복구해야 할 수도 있습니다. 파일이 삭제되면 즉시 시스템에서 제거되지 않습니다. 대신 파일의 메타데이터가 수정되어 해당 공간이 재사용 가능하다는 것을 나타냅니다.

To recover deleted files, you can use tools such as `extundelete`, `foremost`, or `scalpel`. These tools can scan the file system and attempt to recover deleted files based on their metadata.

삭제된 파일을 복구하기 위해 `extundelete`, `foremost`, 또는 `scalpel`과 같은 도구를 사용할 수 있습니다. 이러한 도구는 파일 시스템을 스캔하고 메타데이터를 기반으로 삭제된 파일을 복구하려고 시도할 수 있습니다.

For example, you can use the command `extundelete /dev/sda1 --restore-all` to recover all deleted files on the `/dev/sda1` partition.

예를 들어, `extundelete /dev/sda1 --restore-all` 명령을 사용하여 `/dev/sda1` 파티션에서 삭제된 모든 파일을 복구할 수 있습니다.
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
더 많은 예제와 정보는 깃허브에서 확인할 수 있습니다: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)



<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 고급 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축하고 자동화**할 수 있습니다.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}



## 사용자 계정 및 로그온 활동 검토

알려진 무단 이벤트와 가까운 시기에 생성되거나 사용된 이상한 이름이나 계정을 확인하기 위해 _**/etc/passwd**_, _**/etc/shadow**_ 및 **보안 로그**를 조사합니다. 또한, 가능한 sudo 브루트 포스 공격을 확인합니다.\
또한, 사용자에게 부여된 예상치 못한 권한을 확인하기 위해 _**/etc/sudoers**_ 및 _**/etc/groups**_와 같은 파일을 확인합니다.\
마지막으로, 암호가 없거나 쉽게 추측할 수 있는 암호를 가진 계정을 찾습니다.

## 파일 시스템 조사

### 악성 코드 조사에서 파일 시스템 구조 분석

악성 코드 사건을 조사할 때, 파일 시스템의 구조는 이벤트의 연속과 악성 코드의 내용을 나타내는 중요한 정보원입니다. 그러나, 악성 코드 작성자들은 파일 타임스탬프를 수정하거나 데이터 저장을 위해 파일 시스템을 피하는 등 이러한 분석을 방해하기 위한 기술을 개발하고 있습니다.

이러한 안티 포렌식 방법에 대응하기 위해 다음을 수행해야 합니다:

- **Autopsy**와 같은 도구를 사용하여 이벤트 타임라인을 시각화하거나 **Sleuth Kit**의 `mactime`을 사용하여 자세한 타임라인 데이터를 분석하여 철저한 타임라인 분석을 수행합니다.
- 공격자가 사용하는 쉘 또는 PHP 스크립트가 포함될 수 있는 시스템의 $PATH에 **예상치 못한 스크립트를 조사**합니다.
- 전통적으로 특수 파일을 포함하고 있지만, 악성 코드 관련 파일이 포함될 수 있는 **/dev**를 조사합니다.
- ".. " (점 점 공백) 또는 "..^G" (점 점 제어-G)와 같은 이름의 **숨겨진 파일 또는 디렉토리**를 검색하여 악성 콘텐츠를 숨길 수 있습니다.
- 다음 명령을 사용하여 **setuid root 파일을 식별**합니다:
```find / -user root -perm -04000 -print```
이 명령은 공격자가 악용할 수 있는 권한이 상승된 파일을 찾습니다.
- 루트킷이나 트로이목마의 존재를 나타낼 수 있는 대량 파일 삭제를 확인하기 위해 inode 테이블의 **삭제 타임스탬프를 검토**합니다.
- 하나를 식별한 후 **연속된 inode를 조사**하여 근처의 악성 파일을 확인합니다.
- 악성 코드에 의해 변경될 수 있는 최근 수정된 파일을 확인하기 위해 **일반적인 이진 디렉토리** (_/bin_, _/sbin_)를 확인합니다.
```bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
```
{% hint style="info" %}
**공격자**는 **파일**이 **정당하게** 보이도록 **시간을 수정**할 수 있지만 **inode**를 수정할 수는 없습니다. 동일한 폴더의 다른 파일들과 동일한 시간에 생성 및 수정되었다고 나타내는 **파일**을 찾았지만 **inode**가 예상치 못하게 큰 경우, 해당 파일의 **타임스탬프가 수정**된 것입니다.
{% endhint %}

## 다른 파일 시스템 버전의 파일 비교

### 파일 시스템 버전 비교 요약

파일 시스템 버전을 비교하고 변경 사항을 정확히 파악하기 위해 간소화된 `git diff` 명령을 사용합니다:

- **새로운 파일을 찾기 위해**, 두 개의 디렉토리를 비교합니다:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **수정된 내용**에 대해서, 특정한 줄을 무시하고 변경 사항을 나열하십시오:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **삭제된 파일을 감지하는 방법**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **필터 옵션** (`--diff-filter`)은 추가된 (`A`), 삭제된 (`D`), 또는 수정된 (`M`) 파일과 같이 특정 변경 사항으로 좁히는 데 도움이 됩니다.
- `A`: 추가된 파일
- `C`: 복사된 파일
- `D`: 삭제된 파일
- `M`: 수정된 파일
- `R`: 이름이 바뀐 파일
- `T`: 유형 변경 (예: 파일에서 심볼릭 링크로)
- `U`: 병합되지 않은 파일
- `X`: 알 수 없는 파일
- `B`: 손상된 파일

## 참고 자료

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **책: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로에서 영웅까지 AWS 해킹 배우기**</summary>

**사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하고 싶으신가요? 또는 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!

* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요. 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**해킹 트릭을 공유하려면** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)에 PR을 제출하세요.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급스러운** 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축하고 자동화**하세요.
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
