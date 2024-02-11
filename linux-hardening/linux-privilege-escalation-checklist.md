# Orodha - Kupandisha Kiwango cha Mamlaka kwenye Linux

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Jiunge na [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server ili kuwasiliana na wadukuzi wenye uzoefu na wawindaji wa tuzo za mdudu!

**Machapisho Kuhusu Kudukua**\
Shiriki na yaliyomo yanayochunguza msisimko na changamoto za kudukua

**Habari za Kudukua za Waktu Halisi**\
Endelea kuwa na habari za haraka za ulimwengu wa kudukua kupitia habari na ufahamu wa wakati halisi

**Matangazo ya Hivi Karibuni**\
Baki na habari za hivi karibuni kuhusu tuzo za mdudu zinazoanzishwa na sasisho muhimu za jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na wadukuzi bora leo!

### **Zana bora ya kutafuta njia za kupandisha kiwango cha mamlaka kwenye Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Taarifa za Mfumo](privilege-escalation/#system-information)

* [ ] Pata **taarifa za OS**
* [ ] Angalia [**PATH**](privilege-escalation/#path), kuna **folda inayoweza kuandikwa**?
* [ ] Angalia [**mazingira ya env**](privilege-escalation/#env-info), kuna maelezo nyeti?
* [ ] Tafuta [**udukuzi wa kernel**](privilege-escalation/#kernel-exploits) **kwa kutumia script** (DirtyCow?)
* [ ] **Angalia** kama [**toleo la sudo linaweza kudukuliwa**](privilege-escalation/#sudo-version)
* [ ] [**Dmesg** uthibitisho wa saini umeshindwa](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Enumerate zaidi ya mfumo ([tarehe, takwimu za mfumo, habari za CPU, wachapishaji](privilege-escalation/#more-system-enumeration))
* [ ] [Tafuta ulinzi zaidi](privilege-escalation/#enumerate-possible-defenses)

### [Drives](privilege-escalation/#drives)

* [ ] Pata orodha ya **drives yaliyosanikishwa**
* [ ] Kuna drive yoyote **isiyosanikishwa**?
* [ ] Kuna **creds** yoyote kwenye fstab?

### [**Programu Zilizosanikishwa**](privilege-escalation/#installed-software)

* [ ] Angalia kama kuna [**programu muhimu**](privilege-escalation/#useful-software) **zilizosanikishwa**
* [ ] Angalia kama kuna [**programu zenye udhaifu**](privilege-escalation/#vulnerable-software-installed) **zilizosanikishwa**

### [Michakato](privilege-escalation/#processes)

* [ ] Je, kuna **programu isiyojulikana inayofanya kazi**?
* [ ] Je, kuna programu inayofanya kazi na **mamlaka zaidi kuliko inavyopaswa kuwa**?
* [ ] Tafuta **udukuzi wa michakato inayofanya kazi** (haswa toleo linalofanya kazi).
* [ ] Je, unaweza **kurekebisha faili ya binary** ya michakato inayofanya kazi?
* [ ] **Fuata michakato** na angalia kama kuna michakato ya kuvutia inayofanya kazi mara kwa mara.
* [ ] Je, unaweza **kusoma** baadhi ya **kumbukumbu ya michakato** ya kuvutia (ambapo nywila zinaweza kuokolewa)?

### [Kazi Zilizopangwa/Cron?](privilege-escalation/#scheduled-jobs)

* [ ] Je, [**PATH** ](privilege-escalation/#cron-path)inabadilishwa na cron fulani na unaweza **kuandika** ndani yake?
* [ ] Kuna [**wildcard** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)katika kazi ya cron?
* [ ] Kuna script [**inayoweza kurekebishwa** ](privilege-escalation/#cron-script-overwriting-and-symlink)inayotekelezwa au iko ndani ya **folda inayoweza kurekebishwa**?
* [ ] Je, umegundua kuwa baadhi ya **script** inaweza kuwa au inatekelezwa [**kwa kawaida sana**](privilege-escalation/#frequent-cron-jobs)? (kila baada ya dakika 1, 2 au 5)

### [Huduma](privilege-escalation/#services)

* [ ] Kuna faili ya **.service inayoweza kuandikwa**?
* [ ] Kuna **binary inayoweza kuandikwa** inayotekelezwa na **huduma**?
* [ ] Kuna **folda inayoweza kuandikwa kwenye PATH ya systemd**?

### [Timers](privilege-escalation/#timers)

* [ ] Kuna **timer inayoweza kuandikwa**?

### [Sockets](privilege-escalation/#sockets)

* [ ] Kuna faili ya **.socket inayoweza kuandikwa**?
* [ ] Je, unaweza **kuwasiliana na soketi yoyote**?
* [ ] **Soketi za HTTP** zenye habari ya kuvutia?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Je, unaweza **kuwasiliana na D-Bus yoyote**?

### [Mtandao](privilege-escalation/#network)

* [ ] Enumerate mtandao ili kujua ulipo
* [ ] Je, kuna **bandari zilizofunguliwa** ambazo haukuweza kufikia kabla ya kupata kifaa ndani ya kompyuta?
* [ ] Je, unaweza **kuchunguza trafiki** kwa
### [Uwezo](privilege-escalation/#capabilities)

* [ ] Je, kuna faili yoyote yenye **uwezo usiotarajiwa**?

### [ACLs](privilege-escalation/#acls)

* [ ] Je, kuna faili yoyote yenye **ACL usiotarajiwa**?

### [Sesheni za Shell Zilizofunguliwa](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**Mipangilio ya SSH yenye thamani ya kuvutia**](privilege-escalation/#ssh-interesting-configuration-values)

### [Faili Zenye Kuvutia](privilege-escalation/#interesting-files)

* [ ] **Faili za Profaili** - Kusoma data nyeti? Kuandika kwa privesc?
* [ ] **Faili za passwd/shadow** - Kusoma data nyeti? Kuandika kwa privesc?
* [ ] **Angalia folda za kawaida zenye data nyeti**
* [ ] **Mahali/Faili Zisizo za Kawaida,** unaweza kuwa na ufikiaji au kubadilisha faili za kutekelezwa
* [ ] **Zimebadilishwa** katika dakika za mwisho
* [ ] **Faili za DB za Sqlite**
* [ ] **Faili Zilizofichwa**
* [ ] **Script/Binari katika PATH**
* [ ] **Faili za Wavuti** (manenosiri?)
* [ ] **Nakala za Hifadhi**?
* [ ] **Faili Zinazojulikana zinazohifadhi manenosiri**: Tumia **Linpeas** na **LaZagne**
* [ ] **Utafutaji wa Kawaida**

### [**Faili Zinazoweza Kuandikwa**](privilege-escalation/#writable-files)

* [ ] **Badilisha maktaba ya python** ili kutekeleza amri za kiholela?
* [ ] Je, unaweza **kubadilisha faili za logi**? Kudukua logtotten
* [ ] Je, unaweza **kubadilisha /etc/sysconfig/network-scripts/**? Dukizo la Centos/Redhat
* [ ] Je, unaweza [**kuandika katika faili za ini, int.d, systemd au rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Mbinu Nyingine**](privilege-escalation/#other-tricks)

* [ ] Je, unaweza [**kutumia NFS kuongeza uwezo**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] Je, unahitaji [**kutoroka kutoka kwenye kifaa cha kizuizi**](privilege-escalation/#escaping-from-restricted-shells)?

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Jiunge na [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) ili kuwasiliana na wadukuzi wenye uzoefu na wawindaji wa tuzo za udhaifu!

**Machapisho ya Udukuzi**\
Shiriki na yaliyomo yanayochunguza msisimko na changamoto za udukuzi

**Habari za Udukuzi za Wakati Halisi**\
Endelea kuwa na habari za ulimwengu wa udukuzi kwa njia ya habari na ufahamu wa wakati halisi

**Matangazo ya Hivi Karibuni**\
Baki na habari za hivi karibuni kuhusu tuzo mpya za udhaifu zinazozinduliwa na sasisho muhimu za jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na wadukuzi bora leo!

<details>

<summary><strong>Jifunze udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
