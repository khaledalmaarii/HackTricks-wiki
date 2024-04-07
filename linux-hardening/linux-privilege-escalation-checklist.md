# Orodha - Kupandisha Mamlaka kwa Linux

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka mwanzo hadi kuwa shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalamu wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../.gitbook/assets/image (377).png" alt=""><figcaption></figcaption></figure>

Jiunge na [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server ili kuwasiliana na wavamizi wenye uzoefu na wawindaji wa zawadi za mdudu!

**Machapisho ya Kuvamia**\
Shiriki na yaliyomo yanayochimba katika msisimko na changamoto za kuvamia

**Habari za Kuvamia za Wakati Halisi**\
Kaa sawa na ulimwengu wa kuvamia unaobadilika haraka kupitia habari za wakati halisi na ufahamu

**Matangazo ya Karibuni**\
Baki mwelewa na zawadi mpya za mdudu zinazoanzishwa na sasisho muhimu za jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na wavamizi bora leo!

### **Zana Bora ya Kutafuta Vectors za Kupandisha Mamlaka kwa Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Taarifa za Mfumo](privilege-escalation/#system-information)

* [ ] Pata **taarifa za OS**
* [ ] Angalia [**PATH**](privilege-escalation/#path), kuna **folda inayoweza kuandikwa**?
* [ ] Angalia [**mazingira ya env**](privilege-escalation/#env-info), kuna maelezo **yanayoweza kuwa nyeti**?
* [ ] Tafuta [**mabadiliko ya kernel**](privilege-escalation/#kernel-exploits) **kwa kutumia script** (DirtyCow?)
* [ ] **Angalia** kama [**toleo la sudo** lina mapungufu](privilege-escalation/#sudo-version)
* [ ] [**Uthibitisho wa saini ya Dmesg umeshindwa**](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Enumerate zaidi ya mfumo ([tarehe, takwimu za mfumo, habari ya CPU, wachapishaji](privilege-escalation/#more-system-enumeration))
* [ ] [Tambua ulinzi zaidi](privilege-escalation/#enumerate-possible-defenses)

### [Madereva](privilege-escalation/#drives)

* [ ] **Pata orodha ya** madereva yaliyofungwa
* [ ] **Kuna dereva lisilofungwa?**
* [ ] **Kuna siri katika fstab?**

### [**Programu Iliyosakinishwa**](privilege-escalation/#installed-software)

* [ ] **Angalia** [**programu muhimu**](privilege-escalation/#useful-software) **iliyosakinishwa**
* [ ] **Angalia** [**programu zenye mapungufu**](privilege-escalation/#vulnerable-software-installed) **iliyosakinishwa**

### [Michakato](privilege-escalation/#processes)

* [ ] Je, kuna **programu isiyojulikana inayofanya kazi**?
* [ ] Je, kuna programu inayofanya kazi na **mamlaka zaidi kuliko inavyopaswa kuwa**?
* [ ] Tafuta **mabadiliko ya michakato inayofanya kazi** (hasa toleo linalofanya kazi).
* [ ] Je, unaweza **kurekebisha faili ya binary** ya mchakato wowote unayefanya kazi?
* [ ] **Fuatilia michakato** na angalia ikiwa kuna mchakato wa kuvutia unafanya kazi mara kwa mara.
* [ ] Je, unaweza **kusoma** baadhi ya **kumbukumbu za mchakato** za kuvutia (ambapo nywila zinaweza kuokolewa)?

### [Kazi za Kipangwa/Cron?](privilege-escalation/#scheduled-jobs)

* [ ] Je, [**PATH** ](privilege-escalation/#cron-path)inabadilishwa na cron fulani na unaweza **kuandika** ndani yake?
* [ ] Kuna [**alama ya nukta** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)katika kazi ya cron?
* [ ] Baadhi ya [**script inayoweza kurekebishwa** ](privilege-escalation/#cron-script-overwriting-and-symlink)inafanyiwa **utekelezaji** au iko ndani ya **folda inayoweza kurekebishwa**?
* [ ] Umegundua kwamba baadhi ya **script** inaweza kuwa au inafanyiwa [**utekelezaji** mara **kwa kawaida sana**](privilege-escalation/#frequent-cron-jobs)? (kila baada ya dakika 1, 2 au 5)

### [Huduma](privilege-escalation/#services)

* [ ] Kuna faili ya **.service inayoweza kuandikwa**?
* [ ] Kuna **binary inayoweza kuandikwa** inayotekelezwa na **huduma**?
* [ ] Kuna **folda inayoweza kuandikwa katika NJIA ya systemd**?

### [Majira](privilege-escalation/#timers)

* [ ] Kuna **timer inayoweza kuandikwa**?

### [Soketi](privilege-escalation/#sockets)

* [ ] Kuna faili ya **.socket inayoweza kuandikwa**?
* [ ] Je, unaweza **kuwasiliana na soketi yoyote**?
* [ ] **Soketi za HTTP** zenye habari za kuvutia?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Je, unaweza **kuwasiliana na D-Bus yoyote**?

### [Mtandao](privilege-escalation/#network)

* [ ] Enumerate mtandao ili kujua uko wapi
* [ ] **Fungua bandari ambazo haukuweza kufikia awali** baada ya kupata kabati ndani ya mashine?
* [ ] Je, unaweza **kuchunguza trafiki** kwa kutumia `tcpdump`?

### [Watumiaji](privilege-escalation/#users)

* [ ] Uorodheshe watumiaji/vikundi **kwa ujumla**
* [ ] Je, una **UID kubwa sana**? Je, **mashine** ni **dhaifu**?
* [ ] Je, unaweza [**kupandisha mamlaka kwa sababu ya kikundi**](privilege-escalation/interesting-groups-linux-pe/) unachohusika nacho?
* [ ] Data ya **ubao wa kunakili**?
* [ ] Sera ya Nywila?
* [ ] Jaribu **kutumia** kila **nywila inayojulikana** uliyoigundua hapo awali kuingia **na kila** mtumiaji **anayeweza iwezekanavyo**. Jaribu pia kuingia bila nywila.

### [NJIA Inayoweza Kuandikwa](privilege-escalation/#writable-path-abuses)

* [ ] Ikiwa una **mamlaka ya kuandika juu ya folda fulani kwenye PATH** unaweza kuwa na uwezo wa kupandisha mamlaka

### [SUDO na Amri za SUID](privilege-escalation/#sudo-and-suid)

* [ ] Je, unaweza kutekeleza **amri yoyote na sudo**? Je, unaweza kutumia kusoma, kuandika au kutekeleza kitu chochote kama root? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Je, kuna **binary ya SUID inayoweza kudukuliwa**? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Je, [**amri za sudo** zinazuiliwa na **njia**? unaweza **kupita** vizuizi](privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] [**Amri ya Sudo/SUID bila njia iliyotajwa**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**Binary ya SUID ikibainisha njia**](privilege-escalation/#suid-binary-with-command-path)? Kupita
* [ ] [**Mkazo wa LD\_PRELOAD**](privilege-escalation/#ld\_preload)
* [ ] [**Ukosefu wa maktaba ya .so katika binary ya SUID**](privilege-escalation/#suid-binary-so-injection) kutoka kwenye folda inayoweza kuandikwa?
* [ ] [**Vidokezo vya SUDO vinapatikana**](privilege-escalation/#reusing-sudo-tokens)? [**Je, unaweza kuunda kibali cha SUDO**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* [ ] Je, unaweza [**kusoma au kurekebisha faili za sudoers**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* [ ] Je, unaweza [**kurekebisha /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)?
* [ ] [**Amri ya OpenBSD DOAS**](privilege-escalation/#doas)
### [Uwezo](privilege-escalation/#capabilities)

* [ ] Je, kuna binary yoyote yenye **uwezo usiotarajiwa**?

### [ACLs](privilege-escalation/#acls)

* [ ] Je, kuna faili yoyote yenye **ACL isiyo ya kawaida**?

### [Vikao vya Shell vilivyofunguliwa](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**Mipangilio Muhimu ya SSH**](privilege-escalation/#ssh-interesting-configuration-values)

### [Faili za Kuvutia](privilege-escalation/#interesting-files)

* [ ] **Faili za Wasifu** - Kusoma data nyeti? Kuandika kwa privesc?
* [ ] **Faili za passwd/shadow** - Kusoma data nyeti? Kuandika kwa privesc?
* [ ] **Angalia folda za kuvutia kwa kuhifadhi data nyeti**
* [ ] **Mahali/Faili za Kigeni,** unaweza kuwa na ufikiaji au kubadilisha faili za kutekelezeka
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
* [ ] Je, unaweza **kubadilisha faili za logi**? Kudukua kwa Logtotten
* [ ] Je, unaweza **kubadilisha /etc/sysconfig/network-scripts/**? Kudukua kwa Centos/Redhat
* [ ] Je, unaweza [**kuandika katika faili za ini, int.d, systemd au rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Mbinu Nyingine**](privilege-escalation/#other-tricks)

* [ ] Je, unaweza [**kutumia NFS kwa kuboresha uwezo**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] Je, unahitaji [**kutoroka kutoka kwenye kabati lenye kizuizi**](privilege-escalation/#escaping-from-restricted-shells)?
