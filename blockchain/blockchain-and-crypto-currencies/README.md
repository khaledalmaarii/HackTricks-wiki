{% hint style="success" %}
Jifunze na zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


## Misingi ya Msingi

- **Mkataba Mjanja** unatambuliwa kama programu zinazotekelezwa kwenye blockchain wakati hali fulani zinakutana, kufanya utekelezaji wa makubaliano bila wakala.
- **Maombi Yaliyosambazwa (dApps)** yanajengwa kwenye mikataba mjanja, yakionyesha kiolesura cha mtumiaji kirafiki na nyuma inayoweza kuangaliwa na kuthibitishwa.
- **Vidakuzi na Sarafu** zinatofautisha ambapo sarafu hutumika kama pesa za kidijitali, wakati vidakuzi vinawakilisha thamani au umiliki katika muktadha maalum.
- **Vidakuzi vya Matumizi** hutoa ufikiaji wa huduma, na **Vidakuzi vya Usalama** vinawakilisha umiliki wa mali.
- **DeFi** inasimama kwa Fedha Zilizosambazwa, ikitoa huduma za kifedha bila mamlaka ya kati.
- **DEX** na **DAOs** hurejelea Jukwaa za Kubadilishana Zilizosambazwa na Mashirika Yaliyosambazwa ya Kujitegemea, mtawalia.

## Mifumo ya Makubaliano

Mifumo ya makubaliano huthibitisha uthibitisho salama na uliokubaliwa wa shughuli kwenye blockchain:
- **Uthibitisho wa Kazi (PoW)** unategemea nguvu ya kompyuta kwa uthibitisho wa shughuli.
- **Uthibitisho wa Hisa (PoS)** unahitaji wathibitishaji kushikilia kiasi fulani cha vidakuzi, kupunguza matumizi ya nishati ikilinganishwa na PoW.

## Mambo Msingi ya Bitcoin

### Shughuli

Shughuli za Bitcoin zinahusisha uhamishaji wa fedha kati ya anwani. Shughuli huthibitishwa kupitia saini za kidijitali, kuhakikisha tu mmiliki wa ufunguo wa faragha anaweza kuanzisha uhamisho.

#### Vipengele muhimu:

- **Shughuli za Multisignature** zinahitaji saini nyingi kuidhinisha shughuli.
- Shughuli zina **vyanzo** (chanzo cha fedha), **marudio** (mahali pa kuelekea), **ada** (iliyolipwa kwa wachimbaji), na **maandishi** (kanuni za shughuli).

### Mtandao wa Lightning

Lengo ni kuboresha uwezo wa Bitcoin kwa kuruhusu shughuli nyingi ndani ya kituo, kisha kutangaza hali ya mwisho tu kwenye blockchain.

## Maswala ya Faragha ya Bitcoin

Mashambulizi ya faragha, kama **Umiliki wa Pamoja wa Ingizo** na **Ugunduzi wa Anwani ya Kubadilisha UTXO**, yanatumia mifumo ya shughuli. Mikakati kama **Mchanganyiko** na **CoinJoin** huimarisha kutokujulikana kwa kuficha viungo vya shughuli kati ya watumiaji.

## Kupata Bitcoins kwa Siri

Njia ni pamoja na biashara ya pesa taslimu, uchimbaji, na kutumia mchanganyiko. **CoinJoin** inachanganya shughuli nyingi kufanya iwe ngumu kufuatilia, wakati **PayJoin** inaficha CoinJoins kama shughuli za kawaida kwa faragha iliyoboreshwa.


# Mashambulizi ya Faragha ya Bitcoin

# Muhtasari wa Mashambulizi ya Faragha ya Bitcoin

Katika ulimwengu wa Bitcoin, faragha ya shughuli na kutokujulikana kwa watumiaji mara nyingi ni masuala ya wasiwasi. Hapa kuna muhtasari rahisi wa njia kadhaa za kawaida ambazo wadukuzi wanaweza kuhatarisha faragha ya Bitcoin.

## **Udhani wa Umiliki wa Ingizo la Kawaida**

Kwa ujumla ni nadra kwa vyanzo kutoka kwa watumiaji tofauti kuunganishwa katika shughuli moja kutokana na ugumu uliopo. Hivyo, **anwani mbili za vyanzo katika shughuli moja mara nyingi huchukuliwa kuwa za mmiliki mmoja**.

## **Ugunduzi wa Anwani ya Kubadilisha UTXO**

UTXO, au **Utoaji wa Shughuli Usioutumiwa**, lazima utumike kabisa katika shughuli. Ikiwa sehemu tu inatumwa kwa anwani nyingine, sehemu iliyobaki inaelekea kwenye anwani mpya ya kubadilisha. Wachunguzi wanaweza kudhani anwani hii mpya inamilikiwa na mtumaji, ikahatarisha faragha.

### Mfano
Kwa kuzuwia hii, huduma za kuchanganya au kutumia anwani nyingi zinaweza kusaidia kuficha umiliki.

## **Mawasiliano kwenye Mitandao ya Kijamii na Vikundi**

Watumiaji mara nyingi huweka anwani zao za Bitcoin mtandaoni, hivyo kuwa **rahisi kuunganisha anwani na mmiliki wake**.

## **Uchambuzi wa Grafu ya Shughuli**

Shughuli zinaweza kuonekana kama grafu, zikifunua uhusiano kati ya watumiaji kulingana na mtiririko wa fedha.

## **Heuristi ya Ingizo Isiyohitajika (Heuristi ya Kubadilisha Bora)**

Heuristi hii inategemea uchambuzi wa shughuli zenye vyanzo na marudio mengi kudhani ni marudio gani yanayorudi kwa mtumaji.

### Mfano
```bash
2 btc --> 4 btc
3 btc     1 btc
```
## **Kutumia Anwani Kwa Lazima Tena**

Washambuliaji wanaweza kutuma kiasi kidogo kwa anwani zilizotumiwa awali, wakitarajia mpokeaji atachanganya kiasi hicho na vipande vingine katika shughuli za baadaye, hivyo kuunganisha anwani pamoja.

### Tabia Sahihi ya Mfuko wa Pesa
Mifuko ya pesa inapaswa kuepuka kutumia sarafu zilizopokelewa kwenye anwani zilizotumiwa tayari, ili kuzuia uvujaji huu wa faragha.

## **Mbinu Nyingine za Uchambuzi wa Blockchain**

- **Mikataba ya Malipo Sahihi:** Shughuli bila mabadiliko inaashiria kuwa kati ya anwani mbili zinazomilikiwa na mtumiaji mmoja.
- **Namba za Mzunguko:** Namba ya mzunguko katika shughuli inaonyesha kuwa ni malipo, na matokeo yasiyo ya mzunguko yanaweza kuwa mabadiliko.
- **Uchambuzi wa Mfumo wa Mfuko:** Mifuko tofauti ina mifumo ya kipekee ya uundaji wa shughuli, kuruhusu wachambuzi kutambua programu iliyotumiwa na labda anwani ya mabadiliko.
- **Ulinganisho wa Kiasi na Wakati:** Kufichua nyakati au kiasi cha shughuli kunaweza kufanya shughuli ziweze kufuatiliwa.

## **Uchambuzi wa Trafiki**

Kwa kufuatilia trafiki ya mtandao, washambuliaji wanaweza kuunganisha shughuli au vitalu kwa anwani za IP, kuhatarisha faragha ya mtumiaji. Hii ni kweli hasa ikiwa kampuni inaendesha nodi nyingi za Bitcoin, ikiboresha uwezo wao wa kufuatilia shughuli.

## Zaidi
Kwa orodha kamili ya mashambulizi na ulinzi wa faragha, tembelea [Faragha ya Bitcoin kwenye Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).


# Shughuli za Bitcoin Zisizojulikana

## Njia za Kupata Bitcoins kwa Siri

- **Shughuli za Fedha Taslimu**: Kupata bitcoin kupitia pesa taslimu.
- **Mbadala wa Fedha Taslimu**: Kununua kadi za zawadi na kuzibadilisha mtandaoni kwa bitcoin.
- **Uchimbaji**: Njia ya faragha zaidi ya kupata bitcoins ni kupitia uchimbaji, hasa unapofanywa peke yako kwa sababu mabwawa ya uchimbaji yanaweza kujua anwani ya IP ya mchimbaji. [Maelezo ya Mabwawa ya Uchimbaji](https://en.bitcoin.it/wiki/Pooled_mining)
- **Wizi**: Kimsingi, kuiba bitcoin kunaweza kuwa njia nyingine ya kupata kwa siri, ingawa ni kinyume cha sheria na sio kupendekezwa.

## Huduma za Kuchanganya

Kwa kutumia huduma ya kuchanganya, mtumiaji anaweza **kutuma bitcoins** na kupokea **bitcoins tofauti badala yake**, hivyo kufanya kuandika mmiliki wa awali kuwa ngumu. Hata hivyo, hii inahitaji imani kwa huduma hiyo kutokuweka kumbukumbu na kurudisha bitcoins halisi. Chaguzi mbadala za kuchanganya ni pamoja na kasinon za Bitcoin.

## CoinJoin

**CoinJoin** inachanganya shughuli nyingi kutoka kwa watumiaji tofauti kuwa moja, ikifanya iwe ngumu kwa yeyote anayejaribu kulinganisha vipande vya kuingiza na vya kutoa. Licha ya ufanisi wake, shughuli zenye vipande vya kipekee vya kuingiza na kutoa bado inaweza kufuatiliwa.

Shughuli za mfano ambazo zinaweza kuwa zimetumia CoinJoin ni `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` na `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Kwa maelezo zaidi, tembelea [CoinJoin](https://coinjoin.io/en). Kwa huduma kama hiyo kwenye Ethereum, angalia [Tornado Cash](https://tornado.cash), ambayo inaficha shughuli na fedha kutoka kwa wachimbaji. 

## PayJoin

Aina ya CoinJoin, **PayJoin** (au P2EP), inaficha shughuli kati ya pande mbili (k.m., mteja na muuzaji) kama shughuli ya kawaida, bila matokeo sawa yanayojulikana ya CoinJoin. Hii inafanya iwe ngumu sana kugundua na inaweza kufuta kanuni ya kawaida ya kumiliki kuingiza inayotumiwa na taasisi za ufuatiliaji wa shughuli.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
**Biashara kama hiyo inaweza kuwa PayJoin, ikiboresha faragha wakati bado inabaki isiyotofautishika na shughuli za kawaida za bitcoin.**

**Matumizi ya PayJoin yanaweza kuvuruga sana njia za uchunguzi za jadi**, ikifanya kuwa maendeleo yanayotia moyo katika harakati za faragha ya shughuli.

# Mbinu Bora za Faragha katika Sarafu za Kielektroniki

## **Mbinu za Synchronization ya Pochi**

Ili kudumisha faragha na usalama, kusawazisha pochi na blockchain ni muhimu. Kuna njia mbili zinazojitokeza:

- **Node kamili**: Kwa kupakua blockchain nzima, node kamili inahakikisha faragha ya juu. Shughuli zote zilizowahi kufanywa zimehifadhiwa kwa kiasia, ikifanya iwe haiwezekani kwa wapinzani kutambua ni shughuli gani au anwani ambazo mtumiaji anavutiwa nazo.
- **Uchujaji wa block upande wa mteja**: Njia hii inahusisha kuunda vichujio kwa kila block katika blockchain, kuruhusu pochi kutambua shughuli husika bila kufichua maslahi maalum kwa wachunguzi wa mtandao. Pochi nyepesi hupakua vichujio hivi, na kuchukua block kamili tu wakati kuna kulinganisha na anwani za mtumiaji.

## **Kutumia Tor kwa Anonimiti**

Kwa kuwa Bitcoin inafanya kazi kwenye mtandao wa rika-kwa-rika, kutumia Tor kunapendekezwa kuficha anwani yako ya IP, ikiboresha faragha unaposhirikiana na mtandao.

## **Kuzuia Kutumia Anwani Tena**

Ili kulinda faragha, ni muhimu kutumia anwani mpya kwa kila shughuli. Kutumia anwani mara kwa mara kunaweza kuhatarisha faragha kwa kuunganisha shughuli kwa kitambulisho kimoja. Pochi za kisasa zinakataza kutumia anwani tena kupitia muundo wao.

## **Mbinu za Faragha ya Shughuli**

- **Shughuli nyingi**: Kugawanya malipo katika shughuli kadhaa kunaweza kuficha kiasi cha shughuli, kuzuia mashambulizi ya faragha.
- **Kuepuka kubadilisha**: Kuchagua shughuli ambazo hazihitaji mabadiliko ya pato kunaboresha faragha kwa kuvuruga njia za kugundua mabadiliko.
- **Patosha mabadiliko mengi**: Ikiwa kuepuka mabadiliko sio jambo linalowezekana, kuzalisha mabadiliko mengi bado kunaweza kuboresha faragha.

# **Monero: Kielelezo cha Anonimiti**

Monero inakabiliana na haja ya anonimiti kamili katika shughuli za kidijitali, ikiweka kiwango kikubwa cha faragha.

# **Ethereum: Gas na Shughuli**

## **Kuelewa Gas**

Gas hupima juhudi za kuhesabu zinazohitajika kutekeleza operesheni kwenye Ethereum, bei yake ikiwa **gwei**. Kwa mfano, shughuli inayogharimu 2,310,000 gwei (au 0.00231 ETH) inahusisha kikomo cha gesi na ada ya msingi, pamoja na bahasha ya kuhamasisha wachimbaji. Watumiaji wanaweza kuweka ada ya juu ili kuhakikisha hawalipi zaidi, na ziada kurudishwa.

## **Kutekeleza Shughuli**

Shughuli kwenye Ethereum inahusisha mtumaji na mpokeaji, ambao wanaweza kuwa anwani za mtumiaji au mikataba mjanja. Wanahitaji ada na lazima zichimbwe. Taarifa muhimu katika shughuli ni mpokeaji, saini ya mtumaji, thamani, data ya hiari, kikomo cha gesi, na ada. Kwa umuhimu, anwani ya mtumaji inahesabiwa kutoka kwa saini, ikiondoa haja ya kuwepo kwake katika data ya shughuli.

Mbinu hizi na mifumo ni msingi kwa yeyote anayetaka kushiriki katika sarafu za kielektroniki huku akipatia kipaumbele faragha na usalama.

## Marejeo

* [https://en.wikipedia.org/wiki/Proof\_of\_stake](https://en.wikipedia.org/wiki/Proof\_of\_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced\_address\_reuse)
