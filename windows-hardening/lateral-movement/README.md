# Lateral Movement

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter'da** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**'u takip edin**.
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)**'ya PR göndererek paylaşın**.

</details>

Harici sistemlerde komutları yürütmek için farklı yollar vardır, burada ana Windows yatay hareket tekniklerinin nasıl çalıştığı hakkında açıklamaları bulabilirsiniz:

* [**PsExec**](psexec-and-winexec.md)
* [**SmbExec**](smbexec.md)
* [**WmicExec**](wmicexec.md)
* [**AtExec / SchtasksExec**](atexec.md)
* [**WinRM**](winrm.md)
* [**DCOM Exec**](dcom-exec.md)
* [**Çerez Geçirme**](https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/az-pass-the-cookie) (cloud)
* [**PRT Geçirme**](https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/pass-the-prt) (cloud)
* [**AzureAD Sertifikası Geçirme**](https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/az-pass-the-certificate) (cloud)

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter'da** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**'u takip edin**.
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)**'ya PR göndererek paylaşın**.

</details>
