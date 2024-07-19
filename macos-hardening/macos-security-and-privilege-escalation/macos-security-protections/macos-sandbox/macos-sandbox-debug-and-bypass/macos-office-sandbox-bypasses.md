# macOS Office Sandbox Bypasses

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

### Word Sandbox bypass via Launch Agents

Aplikacja używa **niestandardowego Sandbox** z uprawnieniem **`com.apple.security.temporary-exception.sbpl`** i ten niestandardowy sandbox pozwala na zapisywanie plików wszędzie, pod warunkiem, że nazwa pliku zaczyna się od `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Dlatego, ucieczka była tak prosta jak **napisanie `plist`** LaunchAgent w `~/Library/LaunchAgents/~$escape.plist`.

Sprawdź [**oryginalny raport tutaj**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Word Sandbox bypass via Login Items and zip

Pamiętaj, że od pierwszej ucieczki, Word może zapisywać dowolne pliki, których nazwa zaczyna się od `~$`, chociaż po poprawce poprzedniej luki nie było możliwe zapisywanie w `/Library/Application Scripts` ani w `/Library/LaunchAgents`.

Odkryto, że z poziomu sandboxa można utworzyć **Login Item** (aplikacje, które będą uruchamiane, gdy użytkownik się loguje). Jednak te aplikacje **nie będą się uruchamiać, chyba że** będą **notaryzowane** i **nie można dodać argumentów** (więc nie można po prostu uruchomić odwrotnego powłoki używając **`bash`**).

Z poprzedniej ucieczki Sandbox, Microsoft wyłączył opcję zapisywania plików w `~/Library/LaunchAgents`. Jednak odkryto, że jeśli umieścisz **plik zip jako Login Item**, `Archive Utility` po prostu **rozpakowuje** go w jego bieżącej lokalizacji. Tak więc, ponieważ domyślnie folder `LaunchAgents` w `~/Library` nie jest tworzony, możliwe było **spakowanie plist w `LaunchAgents/~$escape.plist`** i **umieszczenie** pliku zip w **`~/Library`**, aby po dekompresji dotarł do miejsca docelowego.

Sprawdź [**oryginalny raport tutaj**](https://objective-see.org/blog/blog\_0x4B.html).

### Word Sandbox bypass via Login Items and .zshenv

(Pamiętaj, że od pierwszej ucieczki, Word może zapisywać dowolne pliki, których nazwa zaczyna się od `~$`).

Jednak poprzednia technika miała ograniczenie, jeśli folder **`~/Library/LaunchAgents`** istnieje, ponieważ stworzyło go inne oprogramowanie, to by się nie powiodło. Odkryto więc inną sekwencję Login Items dla tego.

Atakujący mógł stworzyć pliki **`.bash_profile`** i **`.zshenv`** z ładunkiem do wykonania, a następnie spakować je i **zapisać zip w folderze** użytkownika ofiary: **`~/~$escape.zip`**.

Następnie, dodać plik zip do **Login Items** i następnie do aplikacji **`Terminal`**. Gdy użytkownik się ponownie loguje, plik zip zostanie rozpakowany w plikach użytkownika, nadpisując **`.bash_profile`** i **`.zshenv`**, a zatem terminal wykona jeden z tych plików (w zależności od tego, czy używana jest bash czy zsh).

Sprawdź [**oryginalny raport tutaj**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Word Sandbox Bypass with Open and env variables

Z procesów w sandboxie nadal możliwe jest wywoływanie innych procesów za pomocą narzędzia **`open`**. Co więcej, te procesy będą działać **w swoim własnym sandboxie**.

Odkryto, że narzędzie open ma opcję **`--env`**, aby uruchomić aplikację z **konkretnymi zmiennymi env**. Dlatego możliwe było stworzenie **pliku `.zshenv`** w folderze **wewnątrz** **sandboxu** i użycie `open` z `--env`, ustawiając **zmienną `HOME`** na ten folder, otwierając aplikację `Terminal`, która wykona plik `.zshenv` (z jakiegoś powodu konieczne było również ustawienie zmiennej `__OSINSTALL_ENVIROMENT`).

Sprawdź [**oryginalny raport tutaj**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Word Sandbox Bypass with Open and stdin

Narzędzie **`open`** obsługiwało również parametr **`--stdin`** (a po poprzedniej ucieczce nie było już możliwe użycie `--env`).

Chodzi o to, że nawet jeśli **`python`** był podpisany przez Apple, **nie wykona** skryptu z atrybutem **`quarantine`**. Jednak możliwe było przekazanie mu skryptu z stdin, więc nie sprawdzi, czy był kwarantannowany, czy nie:&#x20;

1. Umieść plik **`~$exploit.py`** z dowolnymi poleceniami Pythona.
2. Uruchom _open_ **`–stdin='~$exploit.py' -a Python`**, co uruchamia aplikację Python z naszym umieszczonym plikiem jako standardowym wejściem. Python chętnie uruchamia nasz kod, a ponieważ jest to proces potomny _launchd_, nie jest związany z zasadami sandboxu Worda.

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
