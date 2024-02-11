# Uundaji wa Mfano wa Tishio

## Uundaji wa Mfano wa Tishio

Karibu kwenye mwongozo kamili wa HackTricks juu ya Uundaji wa Mfano wa Tishio! Nenda kwenye uchunguzi wa sehemu muhimu ya usalama wa mtandao, ambapo tunatambua, kuelewa, na kuweka mkakati dhidi ya udhaifu wa uwezekano katika mfumo. Mfululizo huu ni mwongozo hatua kwa hatua uliojaa mifano halisi ya ulimwengu, programu muhimu, na maelezo rahisi kueleweka. Ni bora kwa wote wapya na wataalamu wenye uzoefu wanaotaka kuimarisha ulinzi wao wa usalama wa mtandao.

### Matukio Yanayotumiwa Mara kwa Mara

1. **Uundaji wa Programu**: Kama sehemu ya Mzunguko wa Maisha wa Maendeleo ya Programu Salama (SSDLC), uundaji wa mfano wa tishio husaidia katika **utambuzi wa vyanzo vya uwezekano wa udhaifu** katika hatua za awali za maendeleo.
2. **Pentesting**: Mfumo wa Utekelezaji wa Upimaji wa Kuingilia (PTES) unahitaji **uundaji wa mfano wa tishio kuelewa udhaifu wa mfumo** kabla ya kufanya jaribio.

### Mfano wa Tishio kwa Ufupi

Mfano wa Tishio kwa kawaida unawakilishwa kama ramani, picha, au aina nyingine ya taswira inayoonyesha usanifu uliopangwa au ujenzi uliopo wa programu. Inafanana na **ramani ya mtiririko wa data**, lakini tofauti kuu iko katika muundo wake unaolenga usalama.

Mifano ya tishio mara nyingi huonyesha vipengele vilivyowekwa alama kwa rangi nyekundu, ikionyesha udhaifu, hatari, au vizuizi vya uwezekano. Ili kuwezesha mchakato wa utambuzi wa hatari, triadi ya CIA (Uwazi, Uadilifu, Upatikanaji) hutumiwa, ikifanya msingi wa njia nyingi za uundaji wa mfano wa tishio, na STRIDE ikiwa moja ya njia za kawaida. Walakini, njia iliyochaguliwa inaweza kutofautiana kulingana na muktadha na mahitaji maalum.

### Triadi ya CIA

Triadi ya CIA ni mfano unaotambuliwa sana katika uwanja wa usalama wa habari, ikimaanisha Uwazi, Uadilifu, na Upatikanaji. Nguzo hizi tatu hujenga msingi ambao hatua nyingi za usalama na sera zinaundwa, pamoja na njia za uundaji wa mfano wa tishio.

1. **Uwazi**: Kuhakikisha kuwa data au mfumo haufikiwi na watu wasio na idhini. Hii ni sehemu muhimu ya usalama, inahitaji udhibiti sahihi wa ufikiaji, encryption, na hatua zingine za kuzuia uvunjaji wa data.
2. **Uadilifu**: Uwiano, utulivu, na uaminifu wa data katika mzunguko wake wa maisha. Kanuni hii inahakikisha kuwa data haijabadilishwa au kuharibiwa na vyama visivyo na idhini. Mara nyingi inahusisha checksums, hashing, na njia zingine za uthibitisho wa data.
3. **Upatikanaji**: Hii inahakikisha kuwa data na huduma zinapatikana kwa watumiaji walio na idhini wanapohitajika. Mara nyingi inahusisha redundancy, uvumilivu wa hitilafu, na usanidi wa upatikanaji wa juu ili kuendelea kuendesha mifumo hata katika uso wa vikwazo.

### Njia za Uundaji wa Mfano wa Tishio

1. **STRIDE**: Iliyoundwa na Microsoft, STRIDE ni kifupisho cha **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, na Elevation of Privilege**. Kila jamii inawakilisha aina ya tishio, na njia hii mara nyingi hutumiwa katika hatua ya kubuni ya programu au mfumo ili kutambua tishio la uwezekano.
2. **DREAD**: Hii ni njia nyingine kutoka Microsoft inayotumiwa kwa tathmini ya hatari ya tishio lililotambuliwa. DREAD inasimama kwa **Damage potential, Reproducibility, Exploitability, Affected users, na Discoverability**. Kila moja ya sababu hizi hupewa alama, na matokeo hutumiwa kuweka kipaumbele kwa tishio lililotambuliwa.
3. **PASTA** (Mchakato wa Uigaji wa Shambulio na Uchambuzi wa Tishio): Hii ni njia ya hatua saba, **yenye msingi wa hatari**. Inajumuisha ufafanuzi na utambuzi wa malengo ya usalama, kuunda wigo wa kiufundi, uchambuzi wa tishio, uchambuzi wa udhaifu, na tathmini ya hatari / triage.
4. **Trike**: Hii ni njia inayolenga hatari ambayo inazingatia ulinzi wa mali. Inaanza kutoka kwa mtazamo wa **usimamizi wa hatari** na inachunguza tishio na udhaifu katika muktadha huo.
5. **VAST** (Uundaji wa Mfano Rahisi, wa Haraka, na wa Kuona): Njia hii inalenga kuwa rahisi zaidi na inaunganisha katika mazingira ya maendeleo ya Agile. Inachanganya vipengele kutoka njia zingine na inazingatia **taswira za kuona za tishio**.
6. **OCTAVE** (Uchambuzi wa Tishio, Mali, na Udhaifu wa Kazi): Iliyoundwa na Kituo cha Ushirikiano cha CERT, mfumo huu unalenga **tathmini ya hatari ya shirika badala ya mifumo au programu maalum**.

## Zana

Kuna zana na suluhisho za programu kadhaa zinazopatikana ambazo zinaweza **kusaidia** katika uundaji na usimamizi wa mifano ya tishio. Hapa kuna chache unazoweza kuzingatia.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Programu ya chui ya wavuti ya GUI ya msalaba ya juu na yenye vipengele vingi kwa wataalam wa usalama wa mtandao. Spider Suite inaweza kutumika kwa ajili ya kuchora na uchambuzi wa eneo la mashambulizi.

**Matumizi**

1. Chagua URL na Fanya Uchunguzi

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Angalia Grafu

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Mradi wa chanzo wazi kutoka OWASP, Threat Dragon ni programu ya wavuti na desktop ambayo inajumuisha kutengeneza mchoro wa mfumo pamoja na injini ya sheria ya kuzalisha tishio / kupunguza hatari.

**Matumizi**

1. Unda Mradi Mpya

<figure><img src="../.gitbook/assets/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Wakati mwingine inaweza kuonekana kama hii:

<figure><img src="../.gitbook/assets/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Zindua Mradi Mpya

<figure><img src="../.gitbook/assets/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Hifadhi Mradi Mpya

<figure><img src="../.gitbook/assets/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Unda mfano wako

Unaweza kutumia zana kama SpiderSuite Crawler kukupa msukumo, mfano wa msingi ungekuwa kama hii

<figure><img src="../.gitbook/assets/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Kidogo tu ya maelezo kuhusu vitengo:

* Mchakato (Kitengo yenyewe kama Seva ya Wavuti au utendaji wa wavuti)
* Mwigizaji (Mtu kama Mtembeleaji wa Tovuti, Mtumiaji, au Msimamizi)
* Mstari wa Mzunguko wa Data (Kiashiria cha Mwingiliano)
* Mipaka ya Uaminifu (Sehemu tofauti za mtandao au wigo.)
* Uhifadhi (Vitu ambapo data zimehifadhiwa kama vile Databases)

5. Unda Tishio (Hatua ya 1)

Kwanza unapaswa kuchagua safu unayotaka kuong
