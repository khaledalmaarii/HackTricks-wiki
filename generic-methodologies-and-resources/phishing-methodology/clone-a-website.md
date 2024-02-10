<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** isterseniz [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** paylaşın.

</details>


Bazen bir phishing değerlendirmesi için tamamen bir web sitesini **klonlamak** faydalı olabilir.

Unutmayın, kullanıcının sekmesini "kontrol" etmek için klonlanmış web sitesine BeEF kancası gibi bazı yükler ekleyebilirsiniz.

Bu amaçla kullanabileceğiniz farklı araçlar vardır:

## wget
```text
wget -mk -nH
```
## goclone

goclone, a Go-based tool, allows you to clone a website by creating a local copy of the target website's files and directories. This can be useful for phishing attacks or for offline analysis.

### Installation

To install goclone, you can use the following command:

```bash
go get -u github.com/krishpranav/goclone
```

### Usage

To clone a website using goclone, you need to provide the target website's URL and the output directory where the cloned files will be saved. You can use the following command:

```bash
goclone -url <target_url> -out <output_directory>
```

For example, to clone the website `https://www.example.com` and save the cloned files in the `output` directory, you can use the following command:

```bash
goclone -url https://www.example.com -out output
```

### Additional Options

goclone provides some additional options that you can use to customize the cloning process:

- `-depth`: Specifies the maximum depth of the cloning process. By default, goclone will clone the entire website. You can use the `-depth` option to limit the number of levels to be cloned.

- `-exclude`: Specifies a list of directories or files to be excluded from the cloning process. You can use this option to exclude unnecessary files or directories.

- `-cookies`: Specifies a file containing cookies to be used during the cloning process. This can be useful for cloning websites that require authentication.

- `-timeout`: Specifies the timeout for each HTTP request made by goclone. By default, the timeout is set to 10 seconds.

### Conclusion

goclone is a powerful tool that allows you to clone websites easily. However, it is important to use this tool responsibly and ethically.
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Sosyal Mühendislik Araç Seti

### Clone a Website

### Bir Web Sitesini Klonlama

One of the most effective techniques used in phishing attacks is the cloning of legitimate websites. By creating an identical copy of a trusted website, attackers can trick users into entering their sensitive information, such as login credentials or credit card details.

Phishing websites are typically hosted on compromised servers or cloud/SaaS platforms. To clone a website, you will need to follow these steps:

1. Identify the target website: Choose the website you want to clone. It could be a popular social media platform, an online banking portal, or any other site that is likely to attract users.

2. Gather information: Collect as much information as possible about the target website. This includes the website's structure, design, content, and any additional features or functionalities.

3. Set up a phishing server: Create a server that will host the cloned website. This can be done using a cloud/SaaS platform or by compromising a server and installing the necessary software.

4. Clone the website: Use tools like HTTrack or Wget to download the entire website's content, including HTML, CSS, JavaScript, and images. Make sure to preserve the original directory structure and file names.

5. Modify the cloned website: Customize the cloned website to make it look and feel like the original. This includes replicating the design, layout, and branding elements. You may also need to modify the website's code to redirect user inputs to your phishing server.

6. Set up phishing scripts: Implement phishing scripts to capture user inputs, such as login credentials or credit card details. These scripts can be written in languages like PHP or JavaScript and should be integrated into the cloned website.

7. Test the cloned website: Verify that the cloned website is functioning correctly and that the phishing scripts are capturing the desired information. Test it on different devices and browsers to ensure compatibility.

8. Launch the phishing campaign: Once the cloned website is ready, you can start your phishing campaign. This involves sending phishing emails or messages to potential victims, enticing them to visit the cloned website and enter their information.

Remember, phishing is an illegal activity and should only be performed with proper authorization and for legitimate purposes, such as penetration testing or security awareness training.
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** isterseniz [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
