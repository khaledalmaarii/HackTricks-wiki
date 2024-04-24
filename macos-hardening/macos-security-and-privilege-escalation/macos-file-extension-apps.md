# macOS 파일 확장자 및 URL scheme 앱 핸들러

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로부터 영웅이 되는 AWS 해킹 배우기**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드**하고 싶다면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **해킹 요령을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **깃허브 저장소에 제출하세요.**

</details>

## LaunchServices 데이터베이스

macOS에 설치된 모든 애플리케이션의 데이터베이스로, 각 설치된 애플리케이션에 대한 정보를 얻을 수 있는 쿼리할 수 있는 URL schemes 및 MIME 유형과 같은 정보를 얻을 수 있습니다.

다음 명령을 사용하여 이 데이터베이스를 덤프할 수 있습니다:

{% code overflow="wrap" %}
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
{% endcode %}

또는 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) 도구를 사용할 수 있습니다.

**`/usr/libexec/lsd`**는 데이터베이스의 핵심입니다. `.lsd.installation`, `.lsd.open`, `.lsd.openurl` 등과 같은 **여러 XPC 서비스**를 제공합니다. 그러나 또한 애플리케이션에 일부 **권한이 필요**하며, 이를 통해 노출된 XPC 기능을 사용할 수 있습니다. `.launchservices.changedefaulthandler` 또는 `.launchservices.changeurlschemehandler`와 같은 기능을 사용하여 mime 유형이나 URL 스키마에 대한 기본 앱을 변경하거나 기타 작업을 수행할 수 있습니다.

**`/System/Library/CoreServices/launchservicesd`**는 서비스 `com.apple.coreservices.launchservicesd`를 요청하며 실행 중인 애플리케이션에 대한 정보를 얻을 수 있습니다. 시스템 도구인 /**`usr/bin/lsappinfo`** 또는 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html)을 사용하여 조회할 수 있습니다.

## 파일 확장자 및 URL 스키마 앱 핸들러

다음 라인은 확장자에 따라 파일을 열 수 있는 애플리케이션을 찾는 데 유용할 수 있습니다:

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
{% endcode %}

또는 [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps)와 같은 것을 사용할 수 있습니다:
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
당신은 또한 다음을 수행하여 응용 프로그램에서 지원하는 확장자를 확인할 수 있습니다:
```
cd /Applications/Safari.app/Contents
grep -A3 CFBundleTypeExtensions Info.plist  | grep string
<string>css</string>
<string>pdf</string>
<string>webarchive</string>
<string>webbookmark</string>
<string>webhistory</string>
<string>webloc</string>
<string>download</string>
<string>safariextz</string>
<string>gif</string>
<string>html</string>
<string>htm</string>
<string>js</string>
<string>jpg</string>
<string>jpeg</string>
<string>jp2</string>
<string>txt</string>
<string>text</string>
<string>png</string>
<string>tiff</string>
<string>tif</string>
<string>url</string>
<string>ico</string>
<string>xhtml</string>
<string>xht</string>
<string>xml</string>
<string>xbl</string>
<string>svg</string>
```
<details>

<summary><strong>제로부터 영웅이 될 때까지 AWS 해킹 배우기</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF 형식의 HackTricks를 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 굿즈**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f)에 가입하거나 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나** **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **해킹 트릭을 공유하고 싶다면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
