# Linux Environment Variables

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

## Global variables

Vigezo vya kimataifa **vitakuwa** vinarithiwa na **mchakato wa watoto**.

Unaweza kuunda kigezo cha kimataifa kwa ajili ya kikao chako cha sasa kwa kufanya:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Hii variable itapatikana na vikao vyako vya sasa na michakato yake ya watoto.

Unaweza **kuondoa** variable kwa kufanya:
```bash
unset MYGLOBAL
```
## Local variables

Mabadiliko ya **local** yanaweza tu **kupatikana** na **shell/script** ya **sasa**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Orodha ya mabadiliko ya sasa
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – onyesho linalotumiwa na **X**. Kigezo hiki kawaida huwekwa kuwa **:0.0**, ambayo inamaanisha onyesho la kwanza kwenye kompyuta ya sasa.
* **EDITOR** – mhariri wa maandiko anayependelea mtumiaji.
* **HISTFILESIZE** – idadi ya juu ya mistari iliyomo katika faili ya historia.
* **HISTSIZE** – Idadi ya mistari iliyoongezwa kwenye faili ya historia wakati mtumiaji anamaliza kikao chake.
* **HOME** – saraka yako ya nyumbani.
* **HOSTNAME** – jina la mwenyeji wa kompyuta.
* **LANG** – lugha yako ya sasa.
* **MAIL** – mahali ambapo mchanganyiko wa barua wa mtumiaji upo. Kawaida ni **/var/spool/mail/USER**.
* **MANPATH** – orodha ya saraka za kutafuta kurasa za mwongozo.
* **OSTYPE** – aina ya mfumo wa uendeshaji.
* **PS1** – kiashiria cha chaguo-msingi katika bash.
* **PATH** – huhifadhi njia ya saraka zote ambazo zina faili za binary unazotaka kutekeleza kwa kutaja tu jina la faili na si kwa njia ya uhusiano au ya moja kwa moja.
* **PWD** – saraka ya kazi ya sasa.
* **SHELL** – njia ya shell ya amri ya sasa (kwa mfano, **/bin/bash**).
* **TERM** – aina ya terminal ya sasa (kwa mfano, **xterm**).
* **TZ** – eneo lako la muda.
* **USER** – jina lako la mtumiaji la sasa.

## Interesting variables for hacking

### **HISTFILESIZE**

Badilisha **thamani ya kigezo hiki kuwa 0**, ili wakati unapo **maliza kikao chako** faili ya **historia** (\~/.bash\_history) **itafutwa**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Badilisha **thamani ya hii variable kuwa 0**, ili wakati unapo **maliza kikao chako** amri yoyote itaongezwa kwenye **faili ya historia** (\~/.bash\_history).
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

Mchakato utatumia **proxy** iliyotangazwa hapa kuungana na mtandao kupitia **http au https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

Mifumo itatumia vyeti vilivyoonyeshwa katika **hizi env variables**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Badilisha jinsi inavyoonekana kwa kiashiria chako.

[**Hii ni mfano**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Mizizi:

![](<../.gitbook/assets/image (897).png>)

Mtumiaji wa kawaida:

![](<../.gitbook/assets/image (740).png>)

Kazi tatu zilizopangwa nyuma:

![](<../.gitbook/assets/image (145).png>)

Kazi moja iliyopangwa nyuma, moja iliyo simamishwa na amri ya mwisho haikukamilika vizuri:

![](<../.gitbook/assets/image (715).png>)


{% hint style="success" %}
Jifunze & fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
