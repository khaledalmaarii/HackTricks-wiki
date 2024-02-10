# qo' vItlhutlh

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>! </strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks ni qay'be'wI' 'e' vItlhutlh:

* **tlhIngan Hol** vItlhutlh **HackTricks** **advertise** **company** **want** **you** **If** **PDF** **HackTricks** **download** **or** **advertised** **company** **your** **see** **to** **want** **you** **If** **PLANS SUBSCRIPTION** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **Check**
* [**PEASS & HackTricks swag**](https://peass.creator-spring.com) **official** **Get**
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) **Discover**, [**NFTs**](https://opensea.io/collection/the-peass-family) **exclusive** **collection** **our** **of** **Family PEASS The**
* **Join** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) **or** [**telegram group**](https://t.me/peass) **or** **follow** **us** **on** **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share** **your** **hacking tricks** **by** **submitting PRs** **to** [**HackTricks**](https://github.com/carlospolop/hacktricks) **and** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github repos** **the** **and**

</details>

## Introduction

**phishing techniques** **nowadays** **used** **are** **that** **understand** **to** **important** **it's** **attempt phishing** **a** **detect** **To**. **post this** **of** **page parent** **the** **to** **go** **you** **I** **recommend** **I** **reason** **some** **like** **name domain** **victim's** **the** **use** **or** **mimic** **somehow** **to** **try** **will attackers** **that** **the** **of aware** **aren't** **it. **uncover** **to** **aren't** **it** **names domain** **different** **completely** **using** **phished** **are** **you** **and** **name domain** **victim's** **the** **like** **reason** **for** **name domain** **called** **is** **domain** `example.com` **is** **your** **If**.

## Domain name variations

**email** **the** **inside** **name domain** **similar** **a** **use** **will** **that** **attempts phishing** **those** **uncover** **to** **easy** **kind** **It's**. **use** **may** **attacker** **an** **names** **phishing** **probable most** **the** **of list** **a** **generate** **to** **enough** **It's** **it** **using** **it** **using** **IP** **any** **is** **if** **check** **just** **or** **registered** **it**.

### Finding suspicious domains

**tools** **following** **the** **of any** **use** **can** **purpose** **this**. **it** **to** **assigned** **IP** **any** **has** **domain** **the** **if** **check** **to** **automatically** **requests DNS** **perform** **also** **will** **tolls these**:

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**the** **in** **technique** **this** **of explanation** **the** **short** **a** **find** **can** **You** **bit-flipping** **with** **windowscom-s** **microsoft-s** **to** **traffic** **hijacking** **security** **news** **computer** **bleeping** **www.** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)** **in** **research** **original** **the** **read** **or** **page parent** **the** **in** **technique** **this** **of explanation** **the** **find** **can**.

For example, a 1 bit modification in the domain microsoft.com can transform it into _windnws.com._\
**Attackers may register as many bit-flipping domains as possible related to the victim to redirect legitimate users to their infrastructure**.


**All possible bit-flipping domain names should be also monitored.**

### Basic checks

**names domain** **suspicious** **potential** **of list** **a** **have** **you** **Once** **HTTPS** **and** **HTTP** **the** **of screenshots** **get** **also** **It's** **look** **deeper** **a** **take** **to** **case** **that** **and** **suspicious** **it's** **if** **suspicious** **the** **inside** **form login** **any** **copy** **have** **they** **if** **to** **interesting** **also** **It's**. **look** **to** **and** **suspicious** **the** **of pages web** **HTTPS** **and** **HTTP** **monitor** **and** **tools similar** **or** **gophish** **of instances** **for** **search** **and** **IPs** **related** **the** **of **ports** **open** **the** **check** **should** **you** **also** **automate** **to** **order** **In** **domain's victim** **of form login** **each** **with** **domains suspicious** **the** **inside** **form login** **each** **with** **domains victim's** **of form login** **each** **compare** **and** **pages web** **suspicious** **the** **of spider** **and** **domains suspicious** **the** **of forms login** **each** **found** **form login** **each** **with** **domains victim's** **of form login** **each** **compare** **and** **something like** `ssdeep` **using** **domain's victim** **of form login** **any** **if** **matches** **domain's victim** **the** **from** **identity** **any** **if** **see** **to** **you** **can** **note** **that** **positive false** **be** **a** **can** **domain suspicious** **a**.

### Advanced checks

**further** **one** **go** **to** **you** **If** **want** **you** **If** **forms login** **of list** **a** **having** **recommend** **would** **I** **I** **automate** **to** **order** **In** **pages web** **suspicious** **the** **and** **domains suspicious** **the** **of search** **and** **more** **for** **search** **and** **domains suspicious** **the** **of pages web** **and** **HTTP** **and** **HTTPS** **monitor** **to** **you** **should** **also** **tools similar** **or** **gophish** **of instances** **for** **search** **and** **IPs** **related** **the** **of **ports** **open** **the** **check** **should** **you** **also** **mistakes** **make** **also** **attackers** **yes** **(minutes/seconds few** **takes** **only** **it) **while** **in** **once** **awhile** **in** **(day every?** **seconds/minutes few** **takes** **only** **it) **while** **in** **once** **and** **domains suspicious** **the** **of pages web** **and** **HTTP** **and** **HTTPS** **monitor** **to** **you** **should** **also** **tools similar** **or** **gophish** **of instances** **for** **search** **and** **IPs** **related** **the** **of **ports** **open** **the** **check** **should** **you** **something like** `ssdeep` **using** **domain's victim** **of form login** **each** **with** **domains suspicious** **the** **of forms login** **each** **found** **form login** **each** **with** **domains victim's** **of form login** **each** **compare** **and** **pages web** **suspicious** **the** **of spider** **and** **domains suspicious** **the** **of forms login** **each** **found** **form login** **each** **with** **domains victim's** **of form login** **each** **compare** **and** **something like** `ssdeep` **using** **domain's victim** **of form login** **any** **if** **matches** **domain's victim** **the** **from** **identity** **any** **if** **see** **to** **you** **can** **note** **that** **positive false** **be** **a** **can** **domain suspicious** **a**.

## Domain names using keywords

**name domain** **victim's** **the** **inside** **name domain** **bigger** **a** **inside** **name domain** **variation** **
### **Qa'Hom Domains**

**Qa'Hom** **vItlhutlh** **newly registered domains** **TLDs** ([Whoxy](https://www.whoxy.com/newly-registered-domains/) **vItlhutlh**) **check** **keywords** **vItlhutlh domains**. **However**, **long domains** **subdomains** **subdomains**, **keyword** **FLD** **appear** **won't** **phishing subdomain** **find**.

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
