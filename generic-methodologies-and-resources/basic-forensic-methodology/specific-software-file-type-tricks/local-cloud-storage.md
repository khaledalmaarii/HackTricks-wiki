# 로컬 클라우드 스토리지

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage)를 사용하여 세계에서 **가장 진보된** 커뮤니티 도구로 **워크플로우**를 쉽게 구축하고 **자동화**하세요.\
오늘 액세스하세요:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

## OneDrive

Windows에서 OneDrive 폴더는 `\Users\<username>\AppData\Local\Microsoft\OneDrive`에 있습니다. 그리고 `logs\Personal` 안에는 동기화된 파일에 대한 흥미로운 데이터가 포함된 `SyncDiagnostics.log` 파일을 찾을 수 있습니다:

* 바이트 단위 크기
* 생성 날짜
* 수정 날짜
* 클라우드의 파일 수
* 폴더의 파일 수
* **CID**: OneDrive 사용자 고유 ID
* 보고서 생성 시간
* OS의 HD 크기

CID를 찾은 후에는 **이 ID가 포함된 파일을 검색하는 것이 좋습니다**. _**\<CID>.ini**_ 및 _**\<CID>.dat**_와 같은 이름의 파일을 찾을 수 있으며, 이 파일에는 OneDrive와 동기화된 파일의 이름과 같은 흥미로운 정보가 포함될 수 있습니다.

## Google Drive

Windows에서 Google Drive의 주요 폴더는 `\Users\<username>\AppData\Local\Google\Drive\user_default`에 있습니다.\
이 폴더에는 계정의 이메일 주소, 파일 이름, 타임스탬프, 파일의 MD5 해시 등의 정보가 포함된 Sync\_log.log라는 파일이 있습니다. 삭제된 파일도 해당 로그 파일에 MD5와 함께 나타납니다.

**`Cloud_graph\Cloud_graph.db`** 파일은 sqlite 데이터베이스로, **`cloud_graph_entry`** 테이블을 포함하고 있습니다. 이 테이블에서는 **동기화된** **파일의 이름**, 수정 시간, 크기 및 파일의 MD5 체크섬을 찾을 수 있습니다.

데이터베이스 **`Sync_config.db`**의 테이블 데이터에는 계정의 이메일 주소, 공유 폴더의 경로 및 Google Drive 버전이 포함되어 있습니다.

## Dropbox

Dropbox는 파일 관리를 위해 **SQLite 데이터베이스**를 사용합니다. 이 데이터베이스는 다음 폴더에서 찾을 수 있습니다:

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

주요 데이터베이스는 다음과 같습니다:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

".dbx" 확장자는 **데이터베이스**가 **암호화**되어 있음을 의미합니다. Dropbox는 **DPAPI**를 사용합니다 ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Dropbox가 사용하는 암호화를 더 잘 이해하려면 [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)을 읽어보세요.

그러나 주요 정보는 다음과 같습니다:

* **엔트로피**: d114a55212655f74bd772e37e64aee9b
* **솔트**: 0D638C092E8B82FC452883F95F355B8E
* **알고리즘**: PBKDF2
* **반복 횟수**: 1066

그 외에도 데이터베이스를 복호화하려면 다음이 필요합니다:

* **암호화된 DPAPI 키**: `NTUSER.DAT\Software\Dropbox\ks\client`의 레지스트리에서 찾을 수 있습니다 (이 데이터를 이진 형식으로 내보내기)
* **`SYSTEM`** 및 **`SECURITY`** 하이브
* **DPAPI 마스터 키**: `\Users\<username>\AppData\Roaming\Microsoft\Protect`에서 찾을 수 있습니다
* Windows 사용자의 **사용자 이름** 및 **비밀번호**

그런 다음 [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)** 도구를 사용할 수 있습니다:**

![](<../../../.gitbook/assets/image (443).png>)

모든 것이 예상대로 진행되면, 도구는 원본을 복구하는 데 필요한 **기본 키**를 표시합니다. 원본을 복구하려면 이 [cyber\_chef 레시피](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\))를 사용하여 기본 키를 레시피의 "비밀번호"로 넣으면 됩니다.

결과로 나온 헥스는 데이터베이스를 암호화하는 데 사용된 최종 키이며, 이를 복호화할 수 있습니다:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
The **`config.dbx`** 데이터베이스에는 다음이 포함됩니다:

* **Email**: 사용자의 이메일
* **usernamedisplayname**: 사용자의 이름
* **dropbox\_path**: 드롭박스 폴더가 위치한 경로
* **Host\_id: Hash**: 클라우드에 인증하는 데 사용됩니다. 이는 웹에서만 취소할 수 있습니다.
* **Root\_ns**: 사용자 식별자

The **`filecache.db`** 데이터베이스는 드롭박스와 동기화된 모든 파일 및 폴더에 대한 정보를 포함합니다. `File_journal` 테이블이 가장 유용한 정보를 포함하고 있습니다:

* **Server\_path**: 서버 내에서 파일이 위치한 경로 (이 경로는 클라이언트의 `host_id`로 선행됩니다).
* **local\_sjid**: 파일의 버전
* **local\_mtime**: 수정 날짜
* **local\_ctime**: 생성 날짜

이 데이터베이스 내의 다른 테이블은 더 흥미로운 정보를 포함합니다:

* **block\_cache**: 드롭박스의 모든 파일 및 폴더의 해시
* **block\_ref**: `block_cache` 테이블의 해시 ID와 `file_journal` 테이블의 파일 ID를 관련짓습니다.
* **mount\_table**: 드롭박스의 공유 폴더
* **deleted\_fields**: 드롭박스에서 삭제된 파일
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage)를 사용하여 세계에서 **가장 진보된** 커뮤니티 도구로 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}
