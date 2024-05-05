# Modbus Protokolü

## Modbus Protokolüne Giriş

Modbus protokolü Endüstriyel Otomasyon ve Kontrol Sistemlerinde yaygın olarak kullanılan bir protokoldür. Modbus, programlanabilir mantık denetleyicileri (PLC'ler), sensörler, aktüatörler ve diğer endüstriyel cihazlar gibi çeşitli cihazlar arasında iletişime olanak tanır. Modbus Protokolünü anlamak önemlidir çünkü bu, ICS'de en çok kullanılan iletişim protokolüdür ve PLC'lere komut sızdırma ve hatta enjekte etme potansiyeli için geniş bir saldırı yüzeyine sahiptir.

Burada, protokolün bağlamını sağlayan kavramlar nokta nokta belirtilerek belirtilmiştir. ICS sistem güvenliğindeki en büyük zorluk, uygulama ve güncelleme maliyetidir. Bu protokoller ve standartlar, hala yaygın olarak kullanılan 80'ler ve 90'larda tasarlanmıştır. Bir endüstride birçok cihaz ve bağlantı olduğundan, cihazların güncellenmesi çok zordur, bu da hackerlara eski protokollerle başa çıkmaları için bir avantaj sağlar. Modbus'a yapılan saldırılar neredeyse kaçınılmazdır çünkü güncelleme yapılmadan kullanılacak ve işleyişi endüstri için kritik olan bir protokoldür.

## İstemci-Sunucu Mimarisi

Modbus Protokolü genellikle İstemci Sunucu Mimarisi olarak kullanılır, burada bir ana cihaz (istemci) bir veya daha fazla köle cihazla (sunucular) iletişimi başlatır. Bu aynı zamanda SPI, I2C vb. ile elektronik ve IoT'de yaygın olarak kullanılan Usta-Köle mimarisi olarak da adlandırılır.

## Seri ve Ethernet Sürümleri

Modbus Protokolü, Seri İletişim ve Ethernet İletişimi için tasarlanmıştır. Seri İletişim, eski sistemlerde yaygın olarak kullanılırken modern cihazlar Ethernet'i destekler ve yüksek veri hızları sunar, modern endüstriyel ağlar için daha uygundur.

## Veri Temsili

Veri, Modbus protokolünde ASCII veya İkili olarak iletilir, ancak ikili format, eski cihazlarla uyumluluğu nedeniyle kullanılır.

## İşlev Kodları

Modbus Protokolü, PLC'leri ve çeşitli kontrol cihazlarını çalıştırmak için kullanılan belirli işlev kodlarının iletilmesiyle çalışır. Bu bölüm, tekrar saldırılarının işlev kodlarını yeniden ileterek yapılabilmesi nedeniyle önemlidir. Eski cihazlar veri iletimine herhangi bir şifreleme desteği sağlamaz ve genellikle bunları bağlayan uzun tellere sahiptir, bu da bu tellerin manipüle edilmesine ve verinin yakalanmasına/enjekte edilmesine neden olur.

## Modbus Adresleme

Ağdaki her cihazın iletişim için gerekli olan benzersiz bir adresi vardır. Modbus RTU, Modbus TCP vb. gibi protokoller adreslemeyi uygulamak için kullanılır ve veri iletimine bir taşıma katmanı gibi hizmet eder. Aktarılan veri, mesajı içeren Modbus protokol formatında olur.

Ayrıca, Modbus, iletilen verinin bütünlüğünü sağlamak için hata kontrolleri de uygular. Ancak en önemlisi, Modbus açık bir standarttır ve herkes cihazlarına uygulayabilir. Bu, bu protokolün küresel bir standart haline gelmesini sağladı ve endüstriyel otomasyon endüstrisinde yaygındır.

Geniş çapta kullanılması ve güncellenmemesi nedeniyle Modbus'a saldırmak, saldırı yüzeyi ile önemli bir avantaj sağlar. ICS, cihazlar arasındaki iletişime son derece bağımlıdır ve bunlara yapılan saldırılar endüstriyel sistemlerin işleyişi için tehlikeli olabilir. Tekrar saldırıları, veri enjeksiyonu, veri sniffing ve sızdırma, Hizmet Reddi, veri sahteciliği vb. saldırılar, iletim ortamı saldırgan tarafından belirlenirse gerçekleştirilebilir.
