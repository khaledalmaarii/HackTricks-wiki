# Proxmark 3

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!HackTricks AWS Red Team Expert</strong></a><strong>!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Find vulnerabilities that matter most so you can fix them faster. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Attacking RFID Systems with Proxmark3

The first thing you need to do is to have a [**Proxmark3**](https://proxmark.com) and [**install the software and it's dependencie**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Attacking MIFARE Classic 1KB

It has **16 sectors**, each of them has **4 blocks** and each block contains **16B**. The UID is in sector 0 block 0 (and can't be altered).\
To access each sector you need **2 keys** (**A** and **B**) which are stored in **block 3 of each sector** (sector trailer). The sector trailer also stores the **access bits** that give the **read and write** permissions on **each block** using the 2 keys.\
2 keys are useful to give permissions to read if you know the first one and write if you know the second one (for example).

Several attacks can be performed
```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```
**Proxmark3** vItlhutlh **eavesdropping** **Tag to Reader communication** **actions** **perform** **allows**. **Sensitive data** **find** **try**. **Card** **communication** **sniff** **just** **could** **plain and cipher text** **knowing** **weak** **used cryptographic operations** **because** **key used calculate** **calculate** **can** (`mfkey64` **tool**).

### **Raw Commands**

**IoT systems** **nonbranded or noncommercial tags** **use** **sometimes**. **Tags** **custom raw commands** **send** **Proxmark3** **can** **case** **this**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
jIqetlh vItlhutlh. card teywI'wI' vItlhutlh. Proxmark3 raw commands bIquvmoH: `hf 14a raw -p -b 7 26`

### Scripts

Proxmark3 software vItlhutlh **automation scripts** vItlhutlh. vItlhutlh, 'ej vItlhutlh 'e' vItlhutlh, 'ej vItlhutlh script name: `script list` vItlhutlh. vItlhutlh, script run vItlhutlh, script name vItlhutlh:
```
proxmark3> script run mfkeys
```
**fuzz tag readers**- **taghchuq** **readers** **fuzz** **script** **lu'a** **create** **jatlh**. **valid card** **data** **copy** **jatlh** **Lua script** **write** **randomize** **bytes** **one or more** **random** **check** **crashes** **reader** **iteration**.

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

**vulnerabilities** **Find** **matter** **most** **fix** **can** **faster**. **Intruder** **attack surface** **tracks**, **proactive threat scans** **runs**, **issues** **finds** **stack** **tech** **whole** **your** **across** **from** **systems cloud** **apps web** **to** **APIs**. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) **today**.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* **cybersecurity company** **work** **Do**? **HackTricks** **in** **advertised** **company** **your** **see** **want** **Do**? **PDF** **in** **HackTricks** **download** **or** **PEASS** **version** **latest** **the** **access** **have** **or** **PLANS SUBSCRIPTION** [**Check**](https://github.com/sponsors/carlospolop)!
* [**NFTs**](https://opensea.io/collection/the-peass-family) [**exclusive**] **collection** **our** [**Family PEASS The**](https://opensea.io/collection/the-peass-family) **Discover**
* **swag HackTricks & PEASS official** [**Get**](https://peass.creator-spring.com)
* **group Discord** [**💬**](https://emojipedia.org/speech-balloon/) **Join** [**the**](https://discord.gg/hRep4RUj7f) **group telegram** **or** [**group**](https://t.me/peass) **me** **follow** **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **repo hacktricks-cloud** **and** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **the** [**PRs submitting**] **tricks hacking** **your Share** **repo hacktricks** **the** **to** **by**.

</details>
