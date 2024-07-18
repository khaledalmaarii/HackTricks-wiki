{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}


<a rel="license" href="https://creativecommons.org/licenses/by-nc/4.0/"><img alt="Creative Commons Lisansı" style="border-width:0" src="https://licensebuttons.net/l/by-nc/4.0/88x31.png" /></a><br>Telif Hakkı © Carlos Polop 2021. Başka şekilde belirtilmedikçe (kitaba kopyalanan harici bilgilerin orijinal yazarlara ait olduğu), Carlos Polop'un <a href="https://github.com/carlospolop/hacktricks">HACK TRICKS</a> metni <a href="https://creativecommons.org/licenses/by-nc/4.0/">Creative Commons Atıf-GayriTicari 4.0 Uluslararası Lisansı (CC BY-NC 4.0)</a> altında lisanslanmıştır.

Lisans: Atıf-GayriTicari 4.0 Uluslararası (CC BY-NC 4.0)<br>İnsan Okunabilir Lisans: https://creativecommons.org/licenses/by-nc/4.0/<br>Tam Hukuki Şartlar: https://creativecommons.org/licenses/by-nc/4.0/legalcode<br>Biçimlendirme: https://github.com/jmatsushita/Creative-Commons-4.0-Markdown/blob/master/licenses/by-nc.markdown<br>

# creative commons

# Atıf-GayriTicari 4.0 Uluslararası

Creative Commons Corporation ("Creative Commons") bir hukuk firması değildir ve hukuki hizmetler veya hukuki danışmanlık sağlamaz. Creative Commons genel lisanslarının dağıtımı, avukat-müvekkil veya diğer ilişkiler yaratmaz. Creative Commons lisanslarını ve ilgili bilgileri "olduğu gibi" temelinde sunar. Creative Commons, lisansları, şartları ve koşulları altında lisanslanan materyalleri veya ilgili bilgileri kullanmaktan kaynaklanan zararlardan dolayı her türlü sorumluluğu reddeder.

## Creative Commons Genel Lisanslarının Kullanımı

Creative Commons genel lisansları, yaratıcıların ve diğer hak sahiplerinin, telif hakkı ve belirli diğer haklara tabi olan orijinal eserleri ve diğer materyalleri paylaşmak için kullanabilecekleri standart bir dizi terim ve koşul sağlar. Aşağıdaki düşünceler yalnızca bilgilendirme amaçlı olup, eksiksiz değildir ve lisanslarımızın bir parçası değildir.

* __Lisans verenler için düşünceler:__ Genel lisanslarımız, telif hakkı ve belirli diğer haklar tarafından kısıtlanan materyalleri halka kullanma izni verme yetkisine sahip olanlar tarafından kullanılmak üzere tasarlanmıştır. Lisanslarımız geri alınamaz. Lisans verenler, uygulamadan önce seçtikleri lisansın şartlarını okumalı ve anlamalıdır. Lisans verenler, materyali beklenildiği gibi halkın yeniden kullanabilmesi için lisanslarımızı uygulamadan önce gerekli tüm hakları güvence altına almalıdır. Lisans verenler, lisansa tabi olmayan herhangi bir materyali açıkça işaretlemelidir. Bu, diğer CC lisanslı materyalleri veya telif hakkı istisnası veya kısıtlaması altında kullanılan materyalleri içerir. [Lisans verenler için daha fazla düşünce](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensors).

* __Halk için düşünceler:__ Genel lisanslarımızdan birini kullanarak, bir lisans veren lisanslanmış materyali belirli şartlar ve koşullar altında kullanma izni verir. Lisans verenin izni herhangi bir nedenle gerekli değilse - örneğin, telif hakkı istisnası veya kısıtlaması nedeniyle - o zaman bu kullanım lisans tarafından düzenlenmez. Lisanslarımız, yalnızca bir lisans verenin yetkili olduğu telif hakkı ve belirli diğer haklar altında izinler verir. Lisanslanmış materyalin kullanımı, diğer nedenlerden dolayı hala kısıtlanabilir, çünkü başkaları materyalde telif hakkı veya diğer haklara sahip olabilir. Bir lisans veren, tüm değişikliklerin işaretlenmesini veya açıklanmasını isteme gibi özel taleplerde bulunabilir. Lisanslarımız tarafından gerekli olmasa da, makul olan yerlerde bu talepleri saygı göstermeniz teşvik edilir. [Halk için daha fazla düşünce](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensees).

# Creative Commons Atıf-GayriTicari 4.0 Uluslararası Genel Lisansı

Lisans Haklarını (aşağıda tanımlandığı şekilde) kullanarak, bu Creative Commons Atıf-GayriTicari 4.0 Uluslararası Genel Lisansı ("Genel Lisans") şartlarına bağlı olduğunuzu kabul eder ve onaylarsınız. Bu Genel Lisansın bir sözleşme olarak yorumlanabileceği ölçüde, bu şartları ve koşulları kabul etmeniz karşılığında Lisans Hakları size verilir ve Lisans veren, Lisanslı Materyali bu şartlar ve koşullar altında kullanıma sunarak elde ettiği faydalar karşılığında size bu hakları verir.

## Bölüm 1 - Tanımlar.

a. __Uyarlanmış Materyal__, Lisanslı Materyal'den türetilen veya Lisanslı Materyal'e dayanan ve Lisans verenin sahip olduğu Telif Hakkı ve Benzer Haklar kapsamında izin gerektiren şekilde çevrilen, değiştirilen, düzenlenen, dönüştürülen veya başka şekilde değiştirilen materyali ifade eder. Bu Genel Lisans için, Lisanslı Materyal bir müzik eseri, performans veya ses kaydı ise, Uyarlanmış Materyal, Lisanslı Materyal'in bir hareketli görüntü ile zamanlama ilişkisinde senkronize edildiği durumda her zaman üretilir.

b. __Adaptörün Lisansı__, Uyarlanmış Materyale yaptığınız katkılardaki Telif Hakkı ve Benzer Haklarınıza uyguladığınız lisansı ifade eder ve bu Genel Lisansın şartlarına uygun olarak yapılır.

c. __Telif Hakkı ve Benzer Haklar__, Telif Hakkı ve Benzer Haklarla yakından ilişkili olan telif hakkı ve/veya telif hakkına sıkı sıkıya bağlı diğer hakları, performans, yayın, ses kaydı ve Sui Generis Veritabanı Hakları dahil olmak üzere, hakların nasıl etiketlendiği veya kategorize edildiğine bakılmaksızın ifade eder. Bu Genel Lisans için, Bölüm 2(b)(1)-(2)'de belirtilen haklar Telif Hakkı ve Benzer Haklar değildir.

d. __Etkili Teknolojik Önlemler__, uygun yetki olmadan atlatılamayan önlemleri ifade eder ve 20 Aralık 1996 tarihinde kabul edilen WIPO Telif Hakkı Sözleşmesi'nin 11. Maddesi uyarınca yükümlülükleri yerine getiren yasalar altında atlatılamaz.

e. __İstisnalar ve Kısıtlamalar__, kullanımınıza tabi olan Telif Hakkı ve Benzer Haklar için geçerli olan hakkaniyet, adil kullanım ve/veya başka bir istisna veya kısıtlama anlamına gelir.

f. __Lisanslı Materyal__, Lisans verenin bu Genel Lisansı uyguladığı sanatsal veya edebi eser, veritabanı veya diğer materyali ifade eder.

g. __Lisanslı Haklar__, Lisans verenin lisanslamaya yetkili olduğu Telif Hakkı ve Benzer Haklarınızın tümüne sınırlı olan ve Lisanslı Materyalin kullanımınıza tabi olan tüm Telif Hakkı ve Benzer Haklarını ifade eder.

h. __Lisans veren__, bu Genel Lisans altında haklar veren birey(ler) veya kurum(lar)ı ifade eder.

i. __GayriTicari__, ticari avantaj veya maddi karşılık amacı gütmeyen anlamına gelir. Bu Genel Lisans için, Lisanslı Materyalin dijital dosya paylaşımı veya benzeri yollarla başka Telif Hakkı ve Benzer Haklar kapsamındaki materyal karşılığında sunulması, bu değişimle ilgili maddi karşılık ödenmediği sürece GayriTicari olarak kabul edilir.

j. __Paylaşım__, Lisanslı Haklar altında izin gerektiren herhangi bir şekilde veya süreçle materyali halka sunmak anlamına gelir, çoğaltma, genel gösterim, genel performans, dağıtım, yayınlama, iletim veya ithalat gibi, ve materyali halka sunmak için, halkın materyale kendi seçtikleri bir yerden ve zamandan erişebileceği şekillerde materyali erişilebilir hale getirmek anlamına gelir.

k. __Sui Generis Veritabanı Hakları__, Avrupa Parlamentosu ve Konseyi'nin 11 Mart 1996 tarihli 96/9/EC Sayılı Direktifi'nden kaynaklanan telif hakkı dışındaki hakları ve dünyanın herhangi bir yerinde diğer esasen eşdeğer hakları ifade eder.

l. __Siz__, bu Genel Lisans altında Lisanslı Hakları kullanma yetkisine sahip olan birey veya kurumu ifade eder. "Sizin" karşılığı vardır.
## Bölüm 2 – Kapsam.

a. ___Lisans verme.___

1. Bu Kamu Lisansı'nın şartlarına tabi olarak, Lisans Sahibi, size Düzenlenmiş Materyal üzerinde Lisanslı Hakları kullanma yetkisi verir:

A. Yalnızca Kar Amacı Gütmeyen amaçlar için Lisanslı Materyali tamamen veya kısmen çoğaltma ve Paylaşma; ve

B. Kar Amacı Gütmeyen amaçlar için Uyarlanmış Materyali üretme, çoğaltma ve Paylaşma.

2. __İstisnalar ve Sınırlamalar.__ Şüpheye mahal vermemek için, İstisnalar ve Sınırlamaların kullanımınıza uygulandığı durumlarda, bu Kamu Lisansı geçerli değildir ve şartlarına uymak zorunda değilsiniz.

3. __Süre.__ Bu Kamu Lisansının süresi Bölüm 6(a)'da belirtilmiştir.

4. __Medya ve formatlar; teknik değişikliklere izin verilir.__ Lisans Sahibi, Lisanslı Hakları şu anda bilinen veya gelecekte oluşturulacak tüm medya ve formatlarda kullanmanıza ve bunu yapabilmek için gerekli teknik değişiklikleri yapmanıza izin verir. Lisans Sahibi, Lisanslı Hakları kullanmak için gerekli teknik değişiklikleri yapmanızı yasaklama veya yetki verme hakkından feragat eder ve/veya böyle yapmanızı engellemek için herhangi bir hakkı veya yetkisi olmadığını kabul eder. Bu Kamu Lisansı kapsamında, yalnızca bu Bölüm 2(a)(4) tarafından yetkilendirilen değişiklikler Adapted Materyal üretmez.

5. __Aşağı akış alıcılar.__

A. __Lisans Sahibinden Teklif – Lisanslı Materyal.__ Lisanslı Materyalin her alıcısı, Lisans Sahibinden bu Kamu Lisansı'nın şartlarına göre Lisanslı Hakları kullanma teklifi alır.

B. __Aşağı akış kısıtlamaları yok.__ Eğer yaparsanız, Lisanslı Materyal üzerinde Lisanslı Hakları kullanma hakkını kısıtlayan herhangi bir ek veya farklı şart veya koşul uygulayamazsınız veya uygulayamazsınız. Lisanslı Materyalin herhangi bir alıcısının Lisanslı Hakları kullanımını kısıtlarsa, Etkili Teknolojik Önlemler uygulayamazsınız.

6. __Onay yok.__ Bu Kamu Lisansında yer alan hiçbir şey, sizin veya Lisanslı Materyalin kullanımınızın, Lisans Sahibi veya diğerleri tarafından sağlanan atıfta bulunma hakkına sahip olduğunuzu veya bununla bağlantılı olduğunuzu, sponsor olduğunuzu veya resmi statü verildiğini iddia etme veya ima etme izni vermez veya böyle bir şeyi ima etmez.

b. ___Diğer haklar.___

1. Ahlaki haklar, bütünlük hakkı gibi haklar bu Kamu Lisansı kapsamında lisanslanmaz, ayrıca tanıtım, gizlilik ve/veya diğer benzer kişilik hakları da lisanslanmaz; ancak mümkün olduğunca, Lisans Sahibi, size Lisanslı Hakları kullanmanıza izin vermek için gerekli olan sınırlı ölçüdeki bu tür hakları iddia etmekten feragat eder ve/veya böyle bir hak iddia etmeyeceğini kabul eder.

2. Patent ve ticari marka hakları bu Kamu Lisansı kapsamında lisanslanmaz.

3. Mümkün olduğunca, Lisans Sahibi, Lisanslı Hakları kullanımınızdan dolayı doğrudan veya gönüllü veya feragat edilebilir yasal veya zorunlu lisanslama düzenlemesi kapsamında bir toplama kuruluşu aracılığıyla sizden telif ücreti talep etme hakkından feragat eder. Diğer tüm durumlarda, Lisans Sahibi, Lisanslı Materyal Kar Amacı Gütmeyen amaçlar dışında kullanıldığında dâhil olmak üzere, böyle telif ücreti talep etme hakkını açıkça saklı tutar.

## Bölüm 3 – Lisans Koşulları.

Lisanslı Haklarınızın kullanımı aşağıdaki koşullara tabidir.

a. ___Atıf.___

1. Eğer Lisanslı Materyali (değiştirilmiş şekilde de olsa) Paylaşırsanız, şunları yapmalısınız:

A. Lisanslı Materyal ile birlikte Lisans Sahibi tarafından sağlanmışsa aşağıdakileri saklamalısınız:

i. Lisanslı Materyalin yaratıcı(lar)ının ve atıfta bulunulacak diğer kişilerin kimliklerini, Lisans Sahibi tarafından talep edilen herhangi bir makul şekilde (belirtilen takma ad da dahil olmak üzere) koruma;

ii. bir telif hakkı bildirimi;

iii. bu Kamu Lisansına atıfta bulunan bir bildirim;

iv. garanti reddine atıfta bulunan bir bildirim;

v. Lisanslı Materyalin URI'si veya bağlantısını mümkün olduğunca içermelisiniz;

B. Lisanslı Materyali değiştirdiyseniz belirtmeli ve önceki değişikliklerin bir göstergesini saklamalısınız; ve

C. Lisanslı Materyalin bu Kamu Lisansı altında lisanslandığını belirtmeli ve bu Kamu Lisansının metnini veya URI'sini veya bağlantısını içermelisiniz.

2. Bölüm 3(a)(1) koşullarını, Lisanslı Materyali Paylaştığınız ortama, araca ve bağlama dayalı olarak makul bir şekilde yerine getirebilirsiniz. Örneğin, gerekli bilgileri içeren bir kaynağa URI veya bağlantı sağlayarak koşulları yerine getirmek makul olabilir.

3. Lisans Sahibi tarafından talep edilmesi halinde, Bölüm 3(a)(1)(A) tarafından gerekli görülen bilgilerden herhangi birini mümkün olduğunca kaldırmalısınız.

4. Ürettiğiniz Uyarlanmış Materyali Paylaşırsanız, Uyarlama Lisansı'nın, Uyarlanmış Materyalin alıcılarının bu Kamu Lisansına uyum sağlamasını engellememesi gerekir.

## Bölüm 4 – Sui Generis Veritabanı Hakları.

Lisanslı Haklarınızın kullanımınıza tabi olan Sui Generis Veritabanı Haklarını içeriyorsa:

a. Şüpheye mahal vermemek için, Bölüm 2(a)(1) size veritabanının içeriğinin tamamını veya önemli bir kısmını Kar Amacı Gütmeyen amaçlar için çıkarma, yeniden kullanma, çoğaltma ve Paylaşma hakkı verir;

b. Eğer veritabanının içeriğinin tamamını veya önemli bir kısmını, Sui Generis Veritabanı Haklarına sahip olduğunuz bir veritabanına dahil ederseniz, o zaman Sui Generis Veritabanı Haklarına sahip olduğunuz veritabanı (ancak içeriği değil) Uyarlanmış Materyaldir; ve

c. Eğer veritabanının içeriğinin tamamını veya önemli bir kısmını Paylaşırsanız, Bölüm 3(a) koşullarına uymanız gerekir.

Şüpheye mahal vermemek için, bu Bölüm 4, Lisanslı Haklarınızın diğer Telif Hakkı ve Benzer Haklarını içeren bu Kamu Lisansı altındaki yükümlülüklerin yerine geçmez ve bunları tamamlar.

## Bölüm 5 – Garanti Reddi ve Sorumluluk Sınırlaması.

a. __Lisans Sahibi tarafından ayrıca üstlenilmediği sürece, mümkün olduğunca, Lisans Sahibi Lisanslı Materyali olduğu gibi ve mevcut olduğu gibi sunar ve Lisanslı Materyal hakkında herhangi bir türde, açık, zımni, yasal veya diğer herhangi bir garanti sunmaz. Bu, başlıca, başlık, satılabilirlik, belirli bir amaca uygunluk, ihlal edilmeme, gizli veya diğer hataların varlığı veya yokluğu, doğruluk veya hataların varlığı veya yokluğu konusunda garanti vermemeyi içerir, bilinse de bilinmese de. Garanti reddinin tamamen veya kısmen izin verilmediği durumlarda, bu reddin size uygulanmayabileceğini unutmayın.__

b. __Mümkün olduğunca, hiçbir durumda Lisans Sahibi, bu Kamu Lisansından veya Lisanslı Materyalin kullanımından kaynaklanan herhangi bir doğrudan, özel, dolaylı, tesadüfi, ardışık, cezai, örnek veya diğer kayıplar, maliyetler, giderler veya zararlardan dolayı size herhangi bir yasal teori (ihmal dahil) veya başka bir şekilde sorumlu olmayacaktır. Zararların, maliyetlerin, giderlerin veya zararların olasılığı hakkında Lisans Sahibinin sizi bilgilendirmiş olması durumunda bile. Sorumluluk sınırlamasının tamamen veya kısmen izin verilmediği durumlarda, bu sınırlamanın size uygulanmayabileceğini unutmayın.__

c. Yukarıda sağlanan garanti reddi ve sorumluluk sınırlaması, mümkün olduğunca, en yakın şekilde mutlak bir reddi ve tüm sorumluluk feragatini temsil edecek şekilde yorumlanacaktır.

## Bölüm 6 – Süre ve Feshetme.

a. Bu Kamu Lisansı burada lisanslanan Telif Hakkı ve Benzer Haklar süresince geçerlidir. Ancak, bu Kamu Lisansına uymazsanız, o zaman bu Kamu Lisansı kapsamındaki haklarınız otomatik olarak sona erer.

b. Lisans Sahibinin 6(a) Bölümü uyarınca Lisanslı Materyali kullanma hakkınız sona erdiğinde, şunlar geri yürürlüğe girer:

1. ihlalin düzeltilmesi tarihinden itibaren 30 gün içinde düzeltilirse otomatik olarak; veya

2. Lisans Sahibi tarafından açıkça geri yürütmeye tabi tutulursa.

Şüpheye mahal vermemek için, bu Bölüm 6(b), Lisans Sahibinin bu Kamu Lisansının ihlalleriniz için çözüm arama hakkını etkilemez.

c. Şüpheye mahal vermemek için, Lisans Sahibi ayrı koşullar veya şartlar altında Lisanslı Materyali sunabilir veya Lisanslı Materyali herhangi bir zamanda dağıtmayı durdurabilir; ancak, bunu yapmak bu Kamu Lisansını sona erdirmez.

d. 1, 5, 6, 7 ve 8. Bölümler bu Kamu Lisansının sona ermesinden sonra da geçerliliğini korur.
## Bölüm 7 – Diğer Şartlar ve Koşullar.

a. Lisans Veren, sizin tarafınızdan iletilen ek veya farklı şartlara bağlı olmayacaktır, açıkça kabul edilmedikçe.

b. Lisanslı Materyal ile ilgili burada belirtilmeyen herhangi bir düzenleme, anlaşma veya anlayış, bu Genel Lisansın şartlarından bağımsızdır ve ayrıdır.

## Bölüm 8 – Yorum.

a. Şüpheye mahal vermemek için, bu Genel Lisans, bu Genel Lisans kapsamında izinsiz yasal olarak yapılabilen herhangi bir Lisanslı Materyal kullanımına kısıtlama getirmez, sınırlamaz, kısıtlamaz veya koşullar eklemeyecektir ve yorumlanmayacaktır.

b. Mümkün olduğunca, bu Genel Lisansın herhangi bir hükmü uygulanamaz kabul edilirse, uygulanabilir hale getirilmesi için gerekli minimum düzeye otomatik olarak yeniden düzenlenecektir. Hüküm düzeltilemezse, bu Genel Lisans'tan çıkarılacak ve kalan şartları ve koşulların uygulanabilirliğini etkilemeyecek şekilde ayrılacaktır.

c. Bu Genel Lisansın hiçbir şartı veya koşulu feragat edilmeyecek ve uyulmamasına izin verilmeyecek, açıkça kabul edilmedikçe.

d. Bu Genel Lisansın hiçbir hükmü, Lisans Veren veya Siz tarafından uygulanan herhangi bir ayrıcalık ve dokunulmazlığı sınırlama veya feragat olarak yorumlanamaz veya yorumlanamaz, herhangi bir yargı veya otoritenin yasal süreçlerinden.
```
Creative Commons is not a party to its public licenses. Notwithstanding, Creative Commons may elect to apply one of its public licenses to material it publishes and in those instances will be considered the “Licensor.” Except for the limited purpose of indicating that material is shared under a Creative Commons public license or as otherwise permitted by the Creative Commons policies published at [creativecommons.org/policies](http://creativecommons.org/policies), Creative Commons does not authorize the use of the trademark “Creative Commons” or any other trademark or logo of Creative Commons without its prior written consent including, without limitation, in connection with any unauthorized modifications to any of its public licenses or any other arrangements, understandings, or agreements concerning use of licensed material. For the avoidance of doubt, this paragraph does not form part of the public licenses.

Creative Commons may be contacted at [creativecommons.org](http://creativecommons.org/).
```
{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR göndererek HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github depolarına katkıda bulunun.**

</details>
{% endhint %}
