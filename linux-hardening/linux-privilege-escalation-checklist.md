# Orodha - Kupandisha Mamlaka kwa Linux

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Jiunge na [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server ili kuwasiliana na wakora wenye uzoefu na wawindaji wa zawadi za mdudu!

**Machapisho ya Kuhack**\
Shiriki na maudhui yanayochimba kina katika msisimko na changamoto za kuhack

**Taarifa za Kuhack za Muda Halisi**\
Kaa up-to-date na ulimwengu wa kuhack wenye kasi kupitia habari na ufahamu wa muda halisi

**Matangazo ya Karibuni**\
Baki mwelewa na zawadi mpya za mdudu zinazoanzishwa na sasisho muhimu za jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na wakora bora leo!

### **Zana Bora ya Kutafuta Vectors za Kupandisha Mamlaka kwa Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Taarifa za Mfumo](privilege-escalation/#taarifa-za-mfumo)

* [ ] Pata **taarifa za OS**
* [ ] Angalia [**PATH**](privilege-escalation/#path), kuna **folda inayoweza kuandikwa**?
* [ ] Angalia [**vigezo vya mazingira**](privilege-escalation/#env-info), kuna maelezo nyeti?
* [ ] Tafuta [**mashambulizi ya kernel**](privilege-escalation/#kernel-exploits) **kwa kutumia script** (DirtyCow?)
* [ ] **Angalia** kama [**toleo la sudo** lina mapungufu](privilege-escalation/#sudo-version)
* [ ] [**Uthibitisho wa saini ya Dmesg umeshindwa**](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Enumerate mfumo zaidi ([tarehe, takwimu za mfumo, habari ya cpu, wachapishaji](privilege-escalation/#more-system-enumeration))
* [ ] [Tambua ulinzi zaidi](privilege-escalation/#enumerate-possible-defenses)

### [Madereva](privilege-escalation/#madereva)

* [ ] **Pata madereva yaliyofungwa**
* [ ] **Kuna dereva lisilofungwa?**
* [ ] **Kuna siri katika fstab?**

### [**Programu Ilizowekwa**](privilege-escalation/#programu-ilizowekwa)

* [ ] **Angalia kwa**[ **programu muhimu**](privilege-escalation/#useful-software) **iliyowekwa**
* [ ] **Angalia kwa** [**programu zenye mapungufu**](privilege-escalation/#vulnerable-software-installed) **ilizowekwa**

### [Michakato](privilege-escalation/#michakato)

* [ ] Je, kuna **programu isiyojulikana inayofanya kazi**?
* [ ] Je, kuna programu inayofanya kazi na **mamlaka zaidi kuliko inavyopaswa kuwa**?
* [ ] Tafuta **mashambulizi ya michakato inayofanya kazi** (hasa toleo linalofanya kazi).
* [ ] Je, unaweza **kurekebisha binary** ya mchakato wowote unaofanya kazi?
* [ ] **Fuata michakato** na angalia ikiwa kuna mchakato wa kuvutia unafanya kazi mara kwa mara.
* [ ] Je, unaweza **kusoma** baadhi ya **kumbukumbu ya mchakato** inayovutia (ambapo nywila zingeweza kuokolewa)?

### [Kazi za Kipangwa/Cron?](privilege-escalation/#kazi-zilizopangwa)

* [ ] Je, [**PATH** ](privilege-escalation/#cron-path)inabadilishwa na cron fulani na unaweza **kuandika** ndani yake?
* [ ] Kuna [**alama za nukta** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)katika kazi ya cron?
* [ ] Baadhi ya [**hati inayoweza kurekebishwa** ](privilege-escalation/#cron-script-overwriting-and-symlink)inatendwa au iko ndani ya **folda inayoweza kurekebishwa**?
* [ ] Umegundua kwamba baadhi ya **hati** inaweza kuwa au inatendwa [**kwa mara nyingi sana**](privilege-escalation/#frequent-cron-jobs)? (kila baada ya dakika 1, 2 au 5)

### [Huduma](privilege-escalation/#huduma)

* [ ] Kuna faili ya **huduma inayoweza kuandikwa**?
* [ ] Kuna **binary inayoweza kuandikwa** inayotendwa na **huduma**?
* [ ] Kuna **folda inayoweza kuandikwa katika NJIA ya systemd**?

### [Vipimajira](privilege-escalation/#vipimajira)

* [ ] Kuna **kipimajira kinachoweza kuandikwa**?

### [Soketi](privilege-escalation/#sockets)

* [ ] Kuna faili ya **socket inayoweza kuandikwa**?
* [ ] Je, unaweza **kuwasiliana na soketi yoyote**?
* [ ] **Soketi za HTTP** zenye habari za kuvutia?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Je, unaweza **kuwasiliana na D-Bus yoyote**?

### [Mtandao](privilege-escalation/#network)

* [ ] Enumerate mtandao ili kujua uko wapi
* [ ] **Fungua bandari ambazo haukuweza kufikia awali** baada ya kupata kabati ndani ya mashine?
* [ ] Je, unaweza **kuchunguza trafiki** kwa kutumia `tcpdump`?

### [Watumiaji](privilege-escalation/#users)

* [ ] Uainishaji wa watumiaji/vikundi **wa kawaida**
* [ ] Je, una **UID kubwa sana**? Je, **mashine** ni **dhaifu**?
* [ ] Je, unaweza [**kupandisha mamlaka kwa sababu ya kikundi**](privilege-escalation/interesting-groups-linux-pe/) unachohusika nacho?
* [ ] Data ya **ubao wa kunakili**?
* [ ] Sera ya Nywila?
* [ ] Jaribu **kutumia** kila **nywila inayojulikana** uliyoigundua hapo awali kuingia **na kila** mtumiaji **anayowezekana**. Jaribu pia kuingia bila nywila.

### [NJIA Inayoweza Kuandikwa](privilege-escalation/#writable-path-abuses)

* [ ] Ikiwa una **mamlaka ya kuandika juu ya folda fulani kwenye PATH** unaweza kuwa na uwezo wa kupandisha mamlaka

### [SUDO na Amri za SUID](privilege-escalation/#sudo-and-suid)

* [ ] Je, unaweza kutekeleza **amri yoyote na sudo**? Je, unaweza kutumia kusoma, kuandika au kutekeleza chochote kama mzizi? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Je, kuna **binary ya SUID inayoweza kudukuliwa**? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Je, [**amri za sudo** zinazuiliwa na **njia**? unaweza **kupita** vizuizi](privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] [**Amri ya Sudo/SUID bila njia iliyotajwa**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**Binary ya SUID ikionyesha njia**](privilege-escalation/#suid-binary-with-command-path)? Kupita
* [ ] [**Mkazo wa LD\_PRELOAD**](privilege-escalation/#ld\_preload)
* [ ] [**Ukosefu wa .so maktaba katika binary ya SUID**](privilege-escalation/#suid-binary-so-injection) kutoka kwenye folda inayoweza kuandikwa?
* [ ] [**Vidokezo vya SUDO vinapatikana**](privilege-escalation/#reusing-sudo-tokens)? [**Je, unaweza kuunda kibali cha SUDO**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* [ ] Je, unaweza [**kusoma au kurekebisha faili za sudoers**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* [ ] Je, unaweza [**kurekebisha /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)?
* [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) amri
### [Uwezo](privilege-escalation/#capabilities)

* [ ] Je, kuna binary yoyote yenye **uwezo usiotarajiwa**?

### [ACLs](privilege-escalation/#acls)

* [ ] Je, kuna faili yoyote yenye **ACL isiyo ya kawaida**?

### [Vikao vya Shell vilivyo Wazi](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**Mipangilio Muhimu ya SSH**](privilege-escalation/#ssh-interesting-configuration-values)

### [Faili za Kuvutia](privilege-escalation/#interesting-files)

* [ ] **Faili za Wasifu** - Kusoma data nyeti? Kuandika kwa privesc?
* [ ] **Faili za passwd/shadow** - Kusoma data nyeti? Kuandika kwa privesc?
* [ ] **Angalia folda za kuvutia kawaida** kwa data nyeti
* [ ] **Mahali/Faili zisizo za Kawaida,** unaweza kuwa na ufikiaji au kubadilisha faili za kutekelezwa
* [ ] **Zimebadilishwa** katika dakika za mwisho
* [ ] **Faili za DB za Sqlite**
* [ ] **Faili za Fichwa**
* [ ] **Script/Binari katika PATH**
* [ ] **Faili za Wavuti** (nywila?)
* [ ] **Nakala za Kuhifadhi**?
* [ ] **Faili Zinazojulikana zenye nywila**: Tumia **Linpeas** na **LaZagne**
* [ ] **Utafutaji wa Kawaida**

### [**Faili Zinazoweza Kuandikwa**](privilege-escalation/#writable-files)

* [ ] **Badilisha maktaba ya python** ili kutekeleza amri za kupindukia?
* [ ] Je, unaweza **kubadilisha faili za logi**? Kudanganya kwa Logtotten
* [ ] Je, unaweza **kubadilisha /etc/sysconfig/network-scripts/**? Kudanganya kwa Centos/Redhat
* [ ] Je, unaweza [**kuandika katika faili za ini, int.d, systemd au rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Mbinu Nyingine**](privilege-escalation/#other-tricks)

* [ ] Je, unaweza [**kutumia NFS kuongeza uwezo**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] Je, unahitaji [**kutoroka kutoka kwenye kabati lenye kizuizi**](privilege-escalation/#escaping-from-restricted-shells)?

<figure><img src="../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Jiunge na [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server ili kuwasiliana na wadukuzi wenye uzoefu na wawindaji wa tuzo za mdudu!

**Machapisho ya Udukuzi**\
Shiriki na maudhui yanayochimba kina katika msisimko na changamoto za udukuzi

**Taarifa za Udukuzi za Wakati Halisi**\
Kaa sawa na ulimwengu wa udukuzi wenye kasi kupitia habari za wakati halisi na ufahamu

**Matangazo Mapya Zaidi**\
Baki mwelewa na tuzo mpya za mdudu zinazoanzishwa na sasisho muhimu za jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na wadukuzi bora leo!
