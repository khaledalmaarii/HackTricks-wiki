# Mazingira ya Linux

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Mazingira ya kawaida

Mazingira ya kawaida **yataurithiwa** na **mchakato wa watoto**.

Unaweza kuunda mazingira ya kawaida kwa kikao chako cha sasa kwa kufanya:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Hii variable itapatikana kwenye vikao vyako vya sasa na michakato yake ya watoto.

Unaweza **kuondoa** variable kwa kufanya:
```bash
unset MYGLOBAL
```
## Variables za ndani

**Variables za ndani** zinaweza kufikiwa tu na **kifaa cha sasa/kielekezi**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Orodha ya mazingira ya sasa

To list the current environment variables in Linux, you can use the following command:

```bash
echo $VARIABLE_NAME
```

Replace `VARIABLE_NAME` with the name of the specific variable you want to display. If you want to list all the variables, you can use the `env` command:

```bash
env
```

This will display a list of all the current environment variables in your Linux system.
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Variables za Kawaida

Kutoka: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** - kuonyesha inayotumiwa na **X**. Kawaida, hii variable imewekwa kama **:0.0**, ambayo inamaanisha kuwa ni kuonyesha ya kwanza kwenye kompyuta ya sasa.
* **EDITOR** - mhariri wa maandishi unaopendelewa na mtumiaji.
* **HISTFILESIZE** - idadi kubwa ya mistari inayoweza kuwa kwenye faili ya historia.
* **HISTSIZE** - Idadi ya mistari inayopaswa kuongezwa kwenye faili ya historia wakati mtumiaji anapomaliza kikao chake.
* **HOME** - saraka yako ya nyumbani.
* **HOSTNAME** - jina la mwenyeji wa kompyuta.
* **LANG** - lugha yako ya sasa.
* **MAIL** - eneo la sanduku la barua pepe la mtumiaji. Kawaida ni **/var/spool/mail/USER**.
* **MANPATH** - orodha ya saraka za kutafuta kurasa za mwongozo.
* **OSTYPE** - aina ya mfumo wa uendeshaji.
* **PS1** - ishara ya amri ya msingi katika bash.
* **PATH** - inahifadhi njia ya saraka zote ambazo zina faili za binary unazotaka kutekeleza kwa kutoa tu jina la faili na sio njia ya kihusishi au kamili.
* **PWD** - saraka ya kazi ya sasa.
* **SHELL** - njia ya kabati ya amri ya sasa (kwa mfano, **/bin/bash**).
* **TERM** - aina ya terminal ya sasa (kwa mfano, **xterm**).
* **TZ** - muda wako wa eneo.
* **USER** - jina lako la mtumiaji la sasa.

## Variables za Kuvutia kwa Udukuzi

### **HISTFILESIZE**

Badilisha **thamani ya variable hii kuwa 0**, ili wakati unapo **maliza kikao chako**, faili ya historia (\~/.bash\_history) **itafutwa**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Badilisha **thamani ya kipekee ya hii variable kuwa 0**, ili wakati unapo **maliza kikao chako**, amri yoyote itakayotumika haitaongezwa kwenye **faili ya historia** (\~/.bash\_history).
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

Mchakato utatumia **proxy** iliyotangazwa hapa kuunganisha na mtandao kupitia **http au https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

Mchakato utaamini vyeti vilivyotajwa katika **hizi variables za mazingira**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Badilisha jinsi kivinjari chako kinavyoonekana.

[**Hii ni mfano**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (87).png>)

Mtumiaji wa kawaida:

![](<../.gitbook/assets/image (88).png>)

Kazi tatu zilizowekwa nyuma:

![](<../.gitbook/assets/image (89).png>)

Kazi moja iliyowekwa nyuma, moja ilisimamishwa na amri ya mwisho haikumalizika kwa usahihi:

![](<../.gitbook/assets/image (90).png>)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
