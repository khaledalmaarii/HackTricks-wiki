# 로컬 클라우드 스토리지

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요. 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 고급스러운 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

Windows에서 OneDrive 폴더는 `\Users\<username>\AppData\Local\Microsoft\OneDrive`에 있습니다. 그리고 `logs\Personal` 폴더 안에는 동기화된 파일에 대한 일부 흥미로운 데이터가 포함된 `SyncDiagnostics.log` 파일을 찾을 수 있습니다:

* 바이트 단위의 크기
* 생성 날짜
* 수정 날짜
* 클라우드의 파일 수
* 폴더의 파일 수
* **CID**: OneDrive 사용자의 고유 ID
* 보고서 생성 시간
* OS의 HD 크기

CID를 찾았다면 **이 ID를 포함하는 파일을 검색**하는 것이 좋습니다. OneDrive와 동기화된 파일의 이름을 포함할 수 있는 _**\<CID>.ini**_ 및 _**\<CID>.dat**_ 파일을 찾을 수 있습니다.

## Google Drive

Windows에서 주요 Google Drive 폴더는 `\Users\<username>\AppData\Local\Google\Drive\user_default`에 있습니다.\
이 폴더에는 Sync\_log.log라는 파일이 있으며, 해당 파일에는 계정의 이메일 주소, 파일 이름, 타임스탬프, 파일의 MD5 해시 등과 같은 정보가 포함되어 있습니다. 삭제된 파일도 해당 로그 파일에 해당 MD5와 함께 나타납니다.

파일 **`Cloud_graph\Cloud_graph.db`**는 **`cloud_graph_entry`** 테이블을 포함하는 sqlite 데이터베이스입니다. 이 테이블에서는 **동기화된 파일의 이름**, 수정 시간, 크기 및 파일의 MD5 체크섬을 찾을 수 있습니다.

데이터베이스 **`Sync_config.db`**의 테이블 데이터에는 계정의 이메일 주소, 공유 폴더의 경로 및 Google Drive 버전이 포함됩니다.

## Dropbox

Dropbox는 파일을 관리하기 위해 **SQLite 데이터베이스**를 사용합니다. 이\
데이터베이스는 다음 폴더에 있습니다:

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

주요 데이터베이스는 다음과 같습니다:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

".dbx" 확장자는 데이터베이스가 **암호화**되었음을 의미합니다. Dropbox는 **DPAPI**를 사용합니다 ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Dropbox가 사용하는 암호화를 더 잘 이해하기 위해 [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)를 읽을 수 있습니다.

그러나 주요 정보는 다음과 같습니다:

* **엔트로피**: d114a55212655f74bd772e37e64aee9b
* **솔트**: 0D638C092E8B82FC452883F95F355B8E
* **알고리즘**: PBKDF2
* **반복 횟수**: 1066

데이터베이스를 복호화하기 위해 필요한 것은 다음과 같습니다:

* **암호화된 DPAPI 키**: 이것은 레지스트리에서 `NTUSER.DAT\Software\Dropbox\ks\client` 안에 찾을 수 있습니다 (이 데이터를 이진 형식으로 내보냅니다)
* **`SYSTEM`** 및 **`SECURITY`** 하이브
* **DPAPI 마스터 키**: 이는 `\Users\<username>\AppData\Roaming\Microsoft\Protect`에서 찾을 수 있습니다
* Windows 사용자의 **사용자 이름**과 **비밀번호**

그런 다음 [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**** 도구를 사용할 수 있습니다:

![](<../../../.gitbook/assets/image (448).png>)

모든 것이 예상대로 진행되면, 도구는 복구해야 할 **기본 키**를 나타낼 것입니다. 원래 키를 복구하려면 이 [cyber\_chef receipt](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\))를 사용하여 기본 키를 "passphrase"로 사용하세요.

결과로 나오는 16진수는 데이터베이스를 암호화하는 데 사용되는 최종 키이며 다음과 같이 복호화할 수 있습니다:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** 데이터베이스에는 다음이 포함되어 있습니다:

* **이메일**: 사용자의 이메일
* **usernamedisplayname**: 사용자의 이름
* **dropbox\_path**: Dropbox 폴더가 위치한 경로
* **Host\_id**: 클라우드에 인증하는 데 사용되는 해시. 이는 웹에서만 취소할 수 있습니다.
* **Root\_ns**: 사용자 식별자

**`filecache.db`** 데이터베이스에는 Dropbox와 동기화된 모든 파일과 폴더에 대한 정보가 포함되어 있습니다. `File_journal` 테이블에는 가장 유용한 정보가 있습니다:

* **Server\_path**: 서버 내에서 파일이 위치한 경로 (이 경로는 클라이언트의 `host_id`로 시작됩니다).
* **local\_sjid**: 파일의 버전
* **local\_mtime**: 수정 날짜
* **local\_ctime**: 생성 날짜

이 데이터베이스의 다른 테이블에는 더 흥미로운 정보가 포함되어 있습니다:

* **block\_cache**: Dropbox의 모든 파일과 폴더의 해시
* **block\_ref**: `block_cache` 테이블의 해시 ID와 `file_journal` 테이블의 파일 ID를 관련시킵니다.
* **mount\_table**: Dropbox의 공유 폴더
* **deleted\_fields**: 삭제된 Dropbox 파일
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 고급스러운 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)**로부터 AWS 해킹을 처음부터 전문가까지 배워보세요!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
