# AD CS Account Persistence

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

**Hii ni muhtasari mdogo wa sura za kudumu za mashine kutoka kwa utafiti mzuri wa [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**

## **Kuelewa Wizi wa Akreditif za Watumiaji Wanaofanya Kazi kwa kutumia Vyeti – PERSIST1**

Katika hali ambapo cheti kinachoruhusu uthibitisho wa kikoa kinaweza kuombwa na mtumiaji, mshambuliaji ana fursa ya **kuomba** na **kuchukua** cheti hiki ili **kuhifadhi kudumu** kwenye mtandao. Kwa kawaida, kiolezo cha `User` katika Active Directory kinaruhusu maombi kama haya, ingawa wakati mwingine kinaweza kuzuiliwa.

Kwa kutumia chombo kinachoitwa [**Certify**](https://github.com/GhostPack/Certify), mtu anaweza kutafuta vyeti halali vinavyowezesha ufikiaji wa kudumu:
```bash
Certify.exe find /clientauth
```
Inasisitizwa kwamba nguvu ya cheti iko katika uwezo wake wa **kujiuthibitisha kama mtumiaji** anayemilikiwa, bila kujali mabadiliko yoyote ya nenosiri, mradi cheti kimebaki **halali**.

Vyeti vinaweza kuombwa kupitia kiolesura cha picha kwa kutumia `certmgr.msc` au kupitia mstari wa amri na `certreq.exe`. Pamoja na **Certify**, mchakato wa kuomba cheti umewekwa rahisi kama ifuatavyo:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Upon successful request, a certificate along with its private key is generated in `.pem` format. To convert this into a `.pfx` file, which is usable on Windows systems, the following command is utilized: 

Baada ya ombi kufanikiwa, cheti pamoja na ufunguo wake wa faragha kinatengenezwa katika muundo wa `.pem`. Ili kubadilisha hii kuwa faili ya `.pfx`, ambayo inaweza kutumika kwenye mifumo ya Windows, amri ifuatayo inatumika:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Faili la `.pfx` linaweza kupakiwa kwenye mfumo wa lengo na kutumika na chombo kinachoitwa [**Rubeus**](https://github.com/GhostPack/Rubeus) kuomba Tiketi ya Kutoa Tiketi (TGT) kwa mtumiaji, ikipanua ufikiaji wa mshambuliaji kwa muda mrefu kama cheti ni **halali** (kawaida mwaka mmoja):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
An important warning is shared about how this technique, combined with another method outlined in the **THEFT5** section, allows an attacker to persistently obtain an account’s **NTLM hash** without interacting with the Local Security Authority Subsystem Service (LSASS), and from a non-elevated context, providing a stealthier method for long-term credential theft.

## **Gaining Machine Persistence with Certificates - PERSIST2**

Another method involves enrolling a compromised system’s machine account for a certificate, utilizing the default `Machine` template which allows such actions. If an attacker gains elevated privileges on a system, they can use the **SYSTEM** account to request certificates, providing a form of **persistence**:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
This access enables the attacker to authenticate to **Kerberos** as the machine account and utilize **S4U2Self** to obtain Kerberos service tickets for any service on the host, effectively granting the attacker persistent access to the machine.

## **Kuongeza Uthibitisho Kupitia Upya Leseni - PERSIST3**

Njia ya mwisho iliyozungumziwa inahusisha kutumia **uhalali** na **muda wa upya** wa mifano ya leseni. Kwa **kuhuisha** leseni kabla ya kuisha, mshambuliaji anaweza kudumisha uthibitisho kwa Active Directory bila haja ya kujiandikisha tiketi za ziada, ambazo zinaweza kuacha alama kwenye seva ya Mamlaka ya Leseni (CA).

Njia hii inaruhusu **mbinu ya kudumu** iliyopanuliwa, ikipunguza hatari ya kugunduliwa kupitia mwingiliano mdogo na seva ya CA na kuepuka uzalishaji wa vitu ambavyo vinaweza kuwajulisha wasimamizi kuhusu uvamizi.
