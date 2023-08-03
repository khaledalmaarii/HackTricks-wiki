<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks的衣物**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


<a rel="license" href="https://creativecommons.org/licenses/by-nc/4.0/"><img alt="知识共享许可证" style="border-width:0" src="https://licensebuttons.net/l/by-nc/4.0/88x31.png" /></a><br>版权所有 © Carlos Polop 2021。除非另有规定（书中复制的外部信息属于原始作者），Carlos Polop的<a href="https://github.com/carlospolop/hacktricks">HACK TRICKS</a>上的文本根据<a href="https://creativecommons.org/licenses/by-nc/4.0/">知识共享署名-非商业性使用 4.0 国际许可协议（CC BY-NC 4.0）</a>许可。

许可证：署名-非商业性使用 4.0 国际许可协议（CC BY-NC 4.0）<br>
可读许可证：https://creativecommons.org/licenses/by-nc/4.0/<br>
完整法律条款：https://creativecommons.org/licenses/by-nc/4.0/legalcode<br>
格式：https://github.com/jmatsushita/Creative-Commons-4.0-Markdown/blob/master/licenses/by-nc.markdown<br>

# 知识共享

# 署名-非商业性使用 4.0 国际许可协议

知识共享公司（“知识共享”）不是律师事务所，不提供法律服务或法律咨询。知识共享公共许可证的分发不会创建律师-客户或其他关系。知识共享按“原样”提供其许可证和相关信息。知识共享对其许可证、根据其条款和条件许可的任何材料，以及任何相关信息不提供任何保证。知识共享尽可能地免除因使用其许可证而导致的损害的所有责任。

## 使用知识共享公共许可证

知识共享公共许可证提供了一套标准的条款和条件，创作者和其他权利持有人可以使用这些条款和条件来共享原创作品和其他受版权和某些其他权利限制的材料。以下考虑仅供参考，不是详尽无遗的，并且不构成我们许可证的一部分。

* __授权者的考虑事项：__ 我们的公共许可证适用于那些被授权以在版权和某些其他权利受限制的情况下以其他方式使用材料的人。我们的许可证是不可撤销的。授权者在应用许可证之前应阅读并理解所选择许可证的条款和条件。授权者还应在应用我们的许可证之前获得所有必要的权利，以便公众可以按预期重用材料。授权者应明确标记任何不受许可证约束的材料。这包括其他CC许可的材料，或者在版权的例外或限制下使用的材料。[更多授权者的考虑事项](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensors)。

* __公众的考虑事项：__ 通过使用我们的公共许可证之一，授权者授予公众根据指定的条款和条件使用许可材料的权限。如果由于任何适用的版权例外或限制的原因，授权者的许可不是必要的，则该使用不受许可证的管制。我们的许可证仅授予授权者有权授予的版权和某些其他权利下的权限。对于其他原因，包括其他人对材料拥有版权或其他权利，对许可材料的使用仍可能受到限制。授权者可以提出特殊要求，例如要求标记或描述所有更改。虽然我们的许可证不要求这样做，但鼓励您在合理的范围内尊重这些要求。[更多公众的考虑事项](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensees)。

# 知识共享署名-非商业性使用 4.0 国际公共许可协议

通过行使许可权（下文定义），您接受并同意受本《知识共享署名-非商业性使用 4.0 国际公共许可协议》（“公共许可证”）的条款和条件的约束。在某种程度上，本公共许可证可被解释为一份合同，您在接受这些条款和条件时被授予许可权，而许可人则因将许可材料提供给公众而获得这些条款和条件下的利益而授予您这些权利。
## 第1节 - 定义。

a. __改编材料__ 指根据许可材料进行翻译、修改、编排、转换或以其他方式修改的受版权和类似权利保护的材料，其中许可材料与移动图像同步。

b. __适配器许可__ 指您根据本公共许可的条款和条件对改编材料中您的版权和类似权利所适用的许可。

c. __版权和类似权利__ 指与版权密切相关的版权和/或类似权利，包括但不限于表演、广播、录音和独创性数据库权利，不考虑这些权利如何被标记或分类。对于本公共许可，第2(b)(1)-(2)节中指定的权利不属于版权和类似权利。

d. __有效技术措施__ 指在没有适当授权的情况下，根据履行1996年12月20日通过的《世界知识产权组织版权条约》第11条义务的法律，不得规避的措施，以及类似的国际协议。

e. __例外和限制__ 指适用于您对许可材料的使用的合理使用、公平交易和/或任何其他版权和类似权利的例外或限制。

f. __许可材料__ 指许可人适用本公共许可的艺术作品、文学作品、数据库或其他材料。

g. __许可权__ 指根据本公共许可的条款和条件授予您的权利，仅限于适用于您对许可材料的使用的所有版权和类似权利，并且许可人有权授权。

h. __许可人__ 指授予本公共许可下权利的个人或实体。

i. __非商业性__ 指不主要用于或针对商业利益或货币补偿。对于本公共许可，通过数字文件共享或类似方式将许可材料与受版权和类似权利保护的其他材料交换，只要在交换过程中没有支付货币补偿，即属于非商业性。

j. __共享__ 指通过任何需要根据许可权获得许可的方式或过程向公众提供材料，例如复制、公开展示、公开表演、分发、传播、通信或进口，并使材料可供公众使用，包括以公众成员可以在他们个人选择的地点和时间访问材料的方式。

k. __独创性数据库权利__ 指除版权外的其他权利，这些权利源自1996年3月11日欧洲议会和理事会关于数据库的法律保护的指令96/9/EC，以及其他在世界各地基本上等效的权利。

l. __您__ 指根据本公共许可行使许可权的个人或实体。您具有相应的含义。

## 第2节 - 范围。

a. ___许可授予.___

1. 根据本公共许可的条款和条件，许可人特此授予您在许可材料中行使许可权的全球范围内、免版税、不可转让、非独占、不可撤销的许可，以便：

A. 仅为非商业目的复制和共享许可材料的全部或部分；和

B. 仅为非商业目的制作、复制和共享改编材料。

2. __例外和限制。__ 为避免疑义，如果例外和限制适用于您的使用，本公共许可不适用，您无需遵守其条款和条件。

3. __期限。__ 本公共许可的期限在第6(a)节中指定。

4. __媒体和格式；允许技术修改。__ 许可人授权您在现有或今后创建的所有媒体和格式中行使许可权，并进行必要的技术修改。许可人放弃和/或同意不主张任何权利或权限，禁止您进行必要的技术修改以行使许可权，包括绕过有效技术措施的技术修改。对于本公共许可，仅仅进行本第2(a)(4)节授权的修改永远不会产生改编材料。

5. __下游接收者。__

A. __许可人的提供 - 许可材料。__ 许可材料的每个接收者自动收到许可人根据本公共许可的条款和条件行使许可权的提供。

B. __无下游限制。__ 如果您对许可材料提供或强加任何额外或不同的条款或条件，或者对许可材料应用任何有效技术措施，以限制任何许可材料的接收者行使许可权。

6. __不作认可。__ 本公共许可中的任何内容都不构成或可能被解释为许可或暗示您与许可人或其他被指定为根据第3(a)(1)(A)(i)节接收归属的人有关联，或者被赞助、认可或授予官方地位。

b. ___其他权利。___

1. 本公共许可不授予道德权利，例如完整性权利，也不授予公开、隐私和/或其他类似的人格权利；然而，在可能的范围内，许可人放弃和/或同意不主张许可人持有的任何此类权利，以允许您行使许可权，但不包括其他情况。

2. 本公共许可不授予专利和商标权利。

3. 在可能的范围内，许可人放弃从您那里收取行使许可权的版税的权利，无论是直接还是通过任何自愿或可放弃的法定或强制性许可计划的收费机构。在所有其他情况下，许可人明确保留收取此类版税的任何权利，包括在许可材料用于非商业目的以外的情况下。 

## 第3节 - 许可条件。

您行使许可权必须明确遵守以下条件。

a. ___归属。___

1. 如果您共享许可材料（包括修改形式），您必须：

A. 如果许可人在许可材料中提供以下内容，则保留以下内容：

i. 许可材料的创作者和任何其他被指定为接收归属的人的身份，以许可人要求的任何合理方式（包括使用化名，如果被指定）；

ii. 版权声明；

iii. 涉及本公共许可的声明；

iv. 免责声明的声明；

v. 在合理可行的范围内，指向许可材料的URI或超链接；

B. 指示您是否修改了许可材料，并保留任何先前的修改指示；和

C. 指示许可材料在本公共许可下许可，并包括本公共许可的文本或URI或超链接。

2. 您可以根据您共享许可材料的媒体、方式和上下文以任何合理的方式满足第3(a)(1)节中的条件。例如，通过提供指向包含所需信息的资源的URI或超链接来满足条件可能是合理的。

3. 如果许可人要求，您必须在合理可行的范围内删除第3(a)(1)(A)节要求的任何信息。

4. 如果您共享您制作的改编材料，您所应用的适配器许可不得阻止改编材料的接收者遵守本公共许可的条款和条件。
## 第4节 - 特殊数据库权利。

如果许可权包括适用于您对许可材料的使用的特殊数据库权利：

a. 为了避免疑问，第2(a)(1)节授予您提取、重用、复制和仅用于非商业目的共享数据库内容的权利；

b. 如果您将全部或大部分数据库内容包含在您拥有特殊数据库权利的数据库中，则您拥有特殊数据库权利的数据库（但不包括其各个内容）是改编材料；

c. 如果您共享全部或大部分数据库内容，则必须遵守第3(a)节中的条件。

为了避免疑问，本第4节是对许可权中包含的其他版权和类似权利下义务的补充，而不是替代。

## 第5节 - 免责声明和责任限制。

a. 除非许可方另行承担，许可方尽可能以原样和现有状态提供许可材料，并且不对许可材料做出任何明示、默示、法定或其他方面的陈述或保证。这包括但不限于所有权、适销性、特定用途的适用性、非侵权、无潜在或其他缺陷、准确性或错误的存在或不存在，无论是否已知或可发现。在不允许完全或部分放弃保证的情况下，本免责声明可能不适用于您。

b. 在法律允许的范围内，无论是基于任何法律理论（包括但不限于过失）还是其他理由，许可方对您不承担任何直接、特殊、间接、附带、后果性、惩罚性、示范性或其他损失、费用、支出或损害赔偿责任，即使许可方已被告知可能发生此类损失、费用、支出或损害。在不允许完全或部分限制责任的情况下，本限制可能不适用于您。

c. 上述免责声明和责任限制应以尽可能接近绝对免责和放弃所有责任的方式解释。

## 第6节 - 期限和终止。

a. 本公共许可证适用于此处许可的版权和类似权利的期限。但是，如果您未能遵守本公共许可证，则您在本公共许可证下的权利将自动终止。

b. 如果您根据第6(a)节的规定失去使用许可材料的权利，则在以下情况下恢复：

1. 在您发现违规行为后30天内纠正违规行为，自动恢复；或

2. 经许可方明确恢复。

为了避免疑问，本第6(b)节不影响许可方寻求您违反本公共许可证的补救措施的任何权利。

c. 为了避免疑问，许可方也可以根据单独的条款或条件提供许可材料，或随时停止分发许可材料；但是，这样做不会终止本公共许可证。

d. 第1、5、6、7和8节在本公共许可证终止后仍然有效。

## 第7节 - 其他条款和条件。

a. 除非明确同意，否则许可方不受您传达的任何额外或不同的条款或条件的约束。

b. 未在此处声明的有关许可材料的任何安排、理解或协议均与本公共许可证的条款和条件是分开且独立的。

## 第8节 - 解释。

a. 为了避免疑问，本公共许可证不会且不应被解释为减少、限制、限制或对根据本公共许可证可以合法进行的任何许可材料的使用施加条件。

b. 在可能的范围内，如果本公共许可证的任何条款被认为无法执行，则应自动进行改革，以使其具备可执行性的最低程度。如果无法进行改革，则应将该条款从本公共许可证中割离，但不影响其余条款和条件的可执行性。

c. 除非明确同意，否则本公共许可证的任何条款或条件都不会被放弃，也不会同意不遵守。

d. 本公共许可证中的任何内容都不构成或不得解释为对许可方或您适用的任何特权和豁免的限制，包括来自任何司法管辖区或权威机构的法律程序。
```
Creative Commons is not a party to its public licenses. Notwithstanding, Creative Commons may elect to apply one of its public licenses to material it publishes and in those instances will be considered the “Licensor.” Except for the limited purpose of indicating that material is shared under a Creative Commons public license or as otherwise permitted by the Creative Commons policies published at [creativecommons.org/policies](http://creativecommons.org/policies), Creative Commons does not authorize the use of the trademark “Creative Commons” or any other trademark or logo of Creative Commons without its prior written consent including, without limitation, in connection with any unauthorized modifications to any of its public licenses or any other arrangements, understandings, or agreements concerning use of licensed material. For the avoidance of doubt, this paragraph does not form part of the public licenses.

Creative Commons may be contacted at [creativecommons.org](http://creativecommons.org/).
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks 仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud)提交 PR 来分享你的黑客技巧**。

</details>
