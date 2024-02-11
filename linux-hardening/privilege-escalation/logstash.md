<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


## Logstash

Logstash hutumiwa kukusanya, kubadilisha, na kutuma magogo kupitia mfumo unaojulikana kama **pipelines**. Pipelines hizi zinaundwa na hatua za **kuingiza**, **kuchuja**, na **kutoa**. Jambo la kuvutia linatokea wakati Logstash inafanya kazi kwenye kompyuta iliyoathiriwa.

### Usanidi wa Mpipa

Pipelines zinasanidiwa kwenye faili **/etc/logstash/pipelines.yml**, ambayo inaorodhesha maeneo ya usanidi wa mipipa:
```yaml
# Define your pipelines here. Multiple pipelines can be defined.
# For details on multiple pipelines, refer to the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
Hii faili inafichua mahali ambapo faili za **.conf**, zinazohifadhi mipangilio ya mifumo ya mabomba, zinapatikana. Wakati wa kutumia moduli ya **Elasticsearch output**, ni kawaida kwa mifumo ya mabomba kuwa na **sifa za Elasticsearch**, ambazo mara nyingi zina uwezo mkubwa kutokana na haja ya Logstash kuandika data kwenye Elasticsearch. Alama za mwanya katika njia za mipangilio huruhusu Logstash kutekeleza mifumo yote inayolingana katika saraka iliyotengwa.

### Kuongeza Uwezo kwa Kutumia Mifumo ya Mabomba Inayoweza Kuandikwa

Kwa kujaribu kuongeza uwezo, kwanza tafuta mtumiaji ambaye huduma ya Logstash inafanya kazi chini yake, kawaida mtumiaji wa **logstash**. Hakikisha unakidhi **mojawapo** ya vigezo hivi:

- Kuwa na **ufikiaji wa kuandika** kwenye faili ya mifumo ya mabomba ya **.conf** **au**
- Faili ya **/etc/logstash/pipelines.yml** inatumia alama za mwanya, na unaweza kuandika kwenye saraka ya lengo

Aidha, lazima kutimizwe **mojawapo** ya hali hizi:

- Uwezo wa kuanzisha upya huduma ya Logstash **au**
- Faili ya **/etc/logstash/logstash.yml** ina **config.reload.automatic: true** imewekwa

Kwa kuwa kuna alama za mwanya katika mipangilio, kuunda faili inayolingana na alama hii ya mwanya inaruhusu utekelezaji wa amri. Kwa mfano:
```bash
input {
exec {
command => "whoami"
interval => 120
}
}

output {
file {
path => "/tmp/output.log"
codec => rubydebug
}
}
```
Hapa, **interval** inaamua mara ngapi amri itatekelezwa kwa sekunde. Katika mfano uliopewa, amri ya **whoami** inatekelezwa kila baada ya sekunde 120, na matokeo yake yanaelekezwa kwenye **/tmp/output.log**.

Kwa kuwa kuna **config.reload.automatic: true** katika **/etc/logstash/logstash.yml**, Logstash itagundua na kutumia moja kwa moja mipangilio mipya au iliyobadilishwa ya mabomba bila haja ya kuanza upya. Ikiwa hakuna alama ya wilcard, mabadiliko bado yanaweza kufanywa kwenye mipangilio iliyopo, lakini tahadhari inashauriwa ili kuepuka usumbufu.


## Marejeo

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
