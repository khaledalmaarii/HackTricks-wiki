# AD CS Domain Persistence

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

**Hii ni muhtasari wa mbinu za kudumu za kikoa zilizoshirikiwa katika [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**. Angalia kwa maelezo zaidi.

## Kuunda Vyeti kwa Vyeti vya CA Vilivyoibiwa - DPERSIST1

Je, unaweza vipi kusema kwamba cheti ni cheti cha CA?

Inaweza kubainika kwamba cheti ni cheti cha CA ikiwa masharti kadhaa yanatimizwa:

- Cheti kimehifadhiwa kwenye seva ya CA, na funguo zake za faragha zimehifadhiwa na DPAPI ya mashine, au na vifaa kama TPM/HSM ikiwa mfumo wa uendeshaji unauunga mkono.
- Sehemu za Mtoaji na Mhusika za cheti zinakubaliana na jina lililoainishwa la CA.
- Kiambatisho cha "CA Version" kinapatikana katika vyeti vya CA pekee.
- Cheti hakina sehemu za Matumizi ya Funguo za Kupanua (EKU).

Ili kutoa funguo za faragha za cheti hiki, zana ya `certsrv.msc` kwenye seva ya CA ndiyo njia inayoungwa mkono kupitia GUI iliyojengwa ndani. Hata hivyo, cheti hiki hakitofautiani na vingine vilivyohifadhiwa ndani ya mfumo; hivyo, mbinu kama [mbinu ya THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) zinaweza kutumika kwa ajili ya kutoa.

Cheti na funguo za faragha pia zinaweza kupatikana kwa kutumia Certipy na amri ifuatayo:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Upon acquiring the CA certificate and its private key in `.pfx` format, tools like [ForgeCert](https://github.com/GhostPack/ForgeCert) can be utilized to generate valid certificates: 

Baada ya kupata cheti cha CA na funguo zake za faragha katika muundo wa `.pfx`, zana kama [ForgeCert](https://github.com/GhostPack/ForgeCert) zinaweza kutumika kutengeneza vyeti halali:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
{% hint style="warning" %}
Mtumiaji anayelengwa kwa ajili ya uongozi wa cheti lazima awe hai na awe na uwezo wa kuthibitisha katika Active Directory ili mchakato ufanikiwe. Uongozi wa cheti kwa akaunti maalum kama krbtgt hauwezi kufanikiwa.
{% endhint %}

Cheti hiki kilichofanywa kuwa **halali** hadi tarehe ya mwisho iliyotajwa na **kama cheti cha CA cha mzizi ni halali** (kawaida kutoka miaka 5 hadi **10+**). Pia ni halali kwa **mashine**, hivyo ikichanganywa na **S4U2Self**, mshambuliaji anaweza **kuendelea kuwepo kwenye mashine yoyote ya domain** kwa muda wote ambao cheti cha CA ni halali.\
Zaidi ya hayo, **vyeti vilivyoundwa** kwa njia hii **haviwezi kufutwa** kwani CA haijui kuhusu hivyo.

## Kuamini Vyeti vya CA vya Kijanja - DPERSIST2

Kituo cha `NTAuthCertificates` kimewekwa ili kuwa na cheti kimoja au zaidi vya **CA** ndani ya sifa yake ya `cacertificate`, ambayo Active Directory (AD) inatumia. Mchakato wa uthibitishaji na **kikundi cha kudhibiti domain** unahusisha kuangalia kituo cha `NTAuthCertificates` kwa kuangalia kipengee kinacholingana na **CA iliyotajwa** katika uwanja wa Mtoaji wa **cheti** kinachothibitishwa. Uthibitishaji unaendelea ikiwa mechi imepatikana.

Cheti cha CA kilichojisaini mwenyewe kinaweza kuongezwa kwenye kituo cha `NTAuthCertificates` na mshambuliaji, ikiwa wana udhibiti juu ya kituo hiki cha AD. Kawaida, ni wanachama wa kundi la **Enterprise Admin**, pamoja na **Domain Admins** au **Administrators** katika **domain ya mzizi wa msitu**, ndio wanapewa ruhusa ya kubadilisha kitu hiki. Wanaweza kuhariri kituo cha `NTAuthCertificates` wakitumia `certutil.exe` na amri `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, au kwa kutumia [**Zana ya Afya ya PKI**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Uwezo huu ni muhimu hasa unapotumika pamoja na njia iliyotajwa hapo awali inayohusisha ForgeCert ili kuunda vyeti kwa njia ya moja kwa moja.

## Usanidi Mbaya wa Kijanja - DPERSIST3

Fursa za **kuendelea kuwepo** kupitia **mabadiliko ya descriptor ya usalama ya sehemu za AD CS** ni nyingi. Mabadiliko yaliyotajwa katika sehemu ya "[Domain Escalation](domain-escalation.md)" yanaweza kutekelezwa kwa uovu na mshambuliaji mwenye ufikiaji wa juu. Hii inajumuisha kuongeza "haki za udhibiti" (mfano, WriteOwner/WriteDACL/n.k.) kwa sehemu nyeti kama:

- Kituo cha **kompyuta ya AD ya seva ya CA**
- Seva ya **RPC/DCOM ya seva ya CA**
- Kila **kituo au kituo cha AD kilichoshuka** katika **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (kwa mfano, kituo cha Templeti za Cheti, kituo cha Mamlaka ya Uthibitishaji, kituo cha NTAuthCertificates, n.k.)
- **Makundi ya AD yaliyopewa haki za kudhibiti AD CS** kwa kawaida au na shirika (kama vile kundi la ndani la Watoa Cheti na wanachama wake)

Mfano wa utekelezaji mbaya ungehusisha mshambuliaji, ambaye ana **idhini za juu** katika domain, kuongeza ruhusa ya **`WriteOwner`** kwenye templeti ya cheti ya **`User`** ya kawaida, huku mshambuliaji akiwa ndiye mwenye haki hiyo. Ili kutumia hili, mshambuliaji angebadilisha kwanza umiliki wa templeti ya **`User`** kuwa wao wenyewe. Baada ya hapo, **`mspki-certificate-name-flag`** ingetengwa kuwa **1** kwenye templeti ili kuwezesha **`ENROLLEE_SUPPLIES_SUBJECT`**, ikiruhusu mtumiaji kutoa Jina Alternatif la Somo katika ombi. Kisha, mshambuliaji angeweza **kujiandikisha** kwa kutumia **templeti**, akichagua jina la **meneja wa domain** kama jina mbadala, na kutumia cheti kilichopatikana kwa uthibitishaji kama DA.


{% hint style="success" %}
Jifunze & fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki hila za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
