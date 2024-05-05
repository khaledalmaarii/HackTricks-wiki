# Mazingira ya Linux

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

**Kikundi cha Usalama cha Kujitahidi**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Mazingira ya Kitaifa

Mazingira ya kitaifa **yataurithiwa na** **mchakato wa watoto**.

Unaweza kuunda mazingira ya kitaifa kwa kikao chako cha sasa kwa kufanya:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Hii variable itapatikana na vikao vyako vya sasa na michakato yake ya watoto.

Unaweza **kuondoa** variable kwa kufanya:
```bash
unset MYGLOBAL
```
## Variables za Kienyeji

**Variables za kienyeji** zinaweza kufikiwa tu na **kifaa cha sasa/maandishi**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Orodhesha mazingira ya sasa
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Vipimo vya Kawaida

Kutoka: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – kiolesura kinachotumiwa na **X**. Kipimo hiki kawaida huwekwa kama **:0.0**, ambayo inamaanisha kiolesura cha kwanza kwenye kompyuta ya sasa.
* **EDITOR** – mhariri wa maandishi unaopendelewa na mtumiaji.
* **HISTFILESIZE** – idadi kubwa ya mistari inayojumuishwa kwenye faili ya historia.
* **HISTSIZE** – Idadi ya mistari inayoongezwa kwenye faili ya historia wakati mtumiaji anamaliza kikao chake.
* **HOME** – saraka yako ya nyumbani.
* **HOSTNAME** – jina la mwenyeji wa kompyuta.
* **LANG** – lugha yako ya sasa.
* **MAIL** – eneo la sanduku la barua pepe la mtumiaji. Kawaida **/var/spool/mail/USER**.
* **MANPATH** – orodha ya saraka za kutafuta kurasa za mwongozo.
* **OSTYPE** – aina ya mfumo wa uendeshaji.
* **PS1** – ishara ya amri ya msingi katika bash.
* **PATH** – inahifadhi njia ya saraka zote zinazoshikilia faili za binary unazotaka kutekeleza kwa kuzitaja kwa jina la faili na sio kwa njia ya kihusishi au kamili.
* **PWD** – saraka ya kazi ya sasa.
* **SHELL** – njia ya kabu ya amri ya sasa (kwa mfano, **/bin/bash**).
* **TERM** – aina ya terminal ya sasa (kwa mfano, **xterm**).
* **TZ** – eneo lako la muda.
* **USER** – jina lako la mtumiaji la sasa.

## Vipimo vya Kuvutia kwa Udukuzi

### **HISTFILESIZE**

Badilisha **thamani ya kipimo hiki iwe 0**, hivyo unapomaliza **kikao chako** faili ya **historia** (\~/.bash\_history) **itafutwa**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Badilisha **thamani ya kigezo hiki iwe 0**, hivyo unapomaliza **kikao chako** amri yoyote haitaongezwa kwenye **faili ya historia** (\~/.bash\_history).
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

Mchakato utatumia **proxy** iliyotangazwa hapa kuunganisha kwenye mtandao kupitia **http au https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL_CERT_FILE & SSL_CERT_DIR

Mchakato utaamini vyeti vilivyoorodheshwa katika **mazingira haya ya mazingira**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Badilisha jinsi dirisha lako la amri linavyoonekana.

[**Hii ni mfano**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (897).png>)

Mtumiaji wa kawaida:

![](<../.gitbook/assets/image (740).png>)

Kazi moja, mbili na tatu zilizowekwa nyuma:

![](<../.gitbook/assets/image (145).png>)

Kazi moja iliyowekwa nyuma, moja imezuiliwa na amri ya mwisho haikumalizika kwa usahihi:

![](<../.gitbook/assets/image (715).png>)

**Kikundi cha Usalama cha Kujitahidi Kwa Bidii**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
