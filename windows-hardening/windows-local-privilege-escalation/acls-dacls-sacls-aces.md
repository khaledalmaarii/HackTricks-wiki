# ACLs - DACLs/SACLs/ACEs

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和自动化由全球最先进的社区工具提供支持的工作流程。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？你想在HackTricks中看到你的公司广告吗？或者你想获得最新版本的PEASS或下载PDF格式的HackTricks吗？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

## **访问控制列表（ACL）**

ACL是一个有序的ACE列表，用于定义对象及其属性的保护措施。每个ACE标识一个安全主体，并指定该安全主体被允许、拒绝或审计的一组访问权限。

对象的安全描述符可以包含两个ACL：

1. 一个DACL，用于标识被允许或拒绝访问的用户和组
2. 一个SACL，用于控制访问的审计方式

当用户尝试访问文件时，Windows系统会运行AccessCheck，并将安全描述符与用户的访问令牌进行比较，评估用户是否被授予访问权限以及访问权限的种类，这取决于设置的ACE。

### **自主访问控制列表（DACL）**

DACL（通常称为ACL）标识被分配或拒绝对对象的访问权限的用户和组。它包含一个对可保护对象的配对ACE（帐户+访问权限）的列表。

### **系统访问控制列表（SACL）**

SACL使得监视对受保护对象的访问成为可能。SACL中的ACE确定在安全事件日志中记录哪些类型的访问。使用监视工具，如果恶意用户尝试访问受保护的对象，这可能会向相关人员发出警报，并且在事件发生的情况下，我们可以使用日志追溯步骤。最后，您可以启用日志记录以排除访问问题。

## 系统如何使用ACL

每个登录到系统的用户都持有一个包含安全信息的访问令牌。当用户登录时，系统会创建一个访问令牌。代表用户执行的每个进程都有一个访问令牌的副本。令牌标识用户、用户的组和用户的特权。令牌还包含一个登录SID（安全标识符），用于标识当前的登录会话。

当线程尝试访问可保护对象时，LSASS（本地安全性机构）要么授予访问权限，要么拒绝访问。为此，LSASS搜索SDS数据流中的DACL（自主访问控制列表），查找适用于线程的ACE。

对象的DACL中的每个ACE指定了允许或拒绝给定安全主体或登录会话的访问权限。如果对象的所有者没有为该对象创建任何DACL中的ACE，系统会立即授予访问权限。

如果LSASS找到ACE，它会将每个ACE中的受托人SID与线程访问令牌中标识的受托人SID进行比较。

### ACEs

在AD中，可以应用于所有可保护对象的ACE有三种主要类型：

| **ACE**                  | **描述**                                                                                                                                                            |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`拒绝访问ACE`**  | 在DACL中使用，表示用户或组明确被拒绝访问对象                                                                                   |
| **`允许访问ACE`** | 在DACL中使用，表示用户或组明确被授予访问对象                                                                                  |
| **`系统审计ACE`**   | 在SACL中使用，当用户或组尝试访问对象时生成审计日志。记录访问是否被授予以及发生的访问类型 |

每个ACE由以下四个组成部分组成：

1. 具有访问对象权限的用户/组的安全标识符（SID）（或以图形方式表示的主体名称）
2. 表示ACE类型的标志（拒绝访问、允许访问或系统审计ACE）
3. 一组指定子容器/对象是否可以从主对象或父对象继承给定ACE条目的标志
4. 一个[访问掩码](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN)，它是一个32位值，定义了授予对象的权限

系统按顺序检查每个ACE，直到发生以下事件之一：

* **拒绝访问ACE明确拒绝**线程访问令牌中列出的受托人的任何请求的访问权限。
* 线程访问令牌中列出的受托人的**一个或多个允许访问ACE**明确授予所有请求的访问权限。
* 已检查所有ACE，并且仍然至少有一个请求的访问权限**未明确允许**，在这种情况下，访问将被隐式**拒绝**。
### ACE的顺序

因为当请求的访问权限被明确授予或拒绝时，系统会停止检查ACE，所以DACL中ACE的顺序很重要。

DACL中ACE的首选顺序被称为“规范”顺序。对于Windows 2000和Windows Server 2003，规范顺序如下：

1. 所有**显式**ACE放置在任何**继承**ACE之前的一个组中。
2. 在**显式**ACE组内，**拒绝访问**ACE放在**允许访问**ACE之前。
3. 在**继承**组内，首先是从**子对象的父对象继承的ACE**，然后是从**祖父对象继承的ACE**，以此类推。之后，**拒绝访问**ACE放在**允许访问**ACE之前。

下图显示了ACE的规范顺序：

### ACE的规范顺序

![ACE](https://www.ntfs.com/images/screenshots/ACEs.gif)

规范顺序确保了以下情况发生：

* 显式的**拒绝访问ACE会被强制执行，而不管是否有显式的允许访问ACE**。这意味着对象的所有者可以定义允许一组用户访问并拒绝该组的子集的权限。
* 所有**显式ACE在任何继承ACE之前被处理**。这与自由访问控制的概念一致：对于子对象（例如文件）的访问取决于子对象的所有者，而不是父对象（例如文件夹）的所有者。子对象的所有者可以直接在子对象上定义权限。结果是继承权限的效果被修改。

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和自动化由全球**最先进**的社区工具提供支持的工作流程。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### GUI示例

这是一个显示ACL、DACL和ACE的文件夹的经典安全选项卡：

![](../../.gitbook/assets/classicsectab.jpg)

如果我们点击**高级按钮**，我们将获得更多选项，如继承：

![](../../.gitbook/assets/aceinheritance.jpg)

如果您添加或编辑安全主体：

![](../../.gitbook/assets/editseprincipalpointers1.jpg)

最后，我们在审核选项卡中有SACL：

![](../../.gitbook/assets/audit-tab.jpg)

### 示例：显式拒绝访问给一个组

在这个示例中，允许访问的组是Everyone，拒绝访问的组是Marketing，是Everyone的一个子集。

您想要拒绝Marketing组访问Cost文件夹。如果Cost文件夹的ACE按照规范顺序排列，拒绝Marketing的ACE会在允许Everyone的ACE之前。

在访问检查期间，操作系统按照它们在对象的DACL中出现的顺序依次处理ACE，因此拒绝的ACE在允许的ACE之前被处理。结果，属于Marketing组的用户被拒绝访问。其他人可以访问该对象。

### 示例：显式优先于继承

在这个示例中，Cost文件夹有一个可继承的ACE，拒绝Marketing（父对象）的访问。换句话说，属于Marketing组的所有用户（或子对象）都被继承拒绝访问。

您想要允许Marketing总监Bob访问Cost文件夹。作为Marketing组的成员，Bob被继承拒绝访问Cost文件夹。子对象（用户Bob）的所有者定义了一个显式ACE，允许访问Cost文件夹。如果子对象的ACE按照规范顺序排列，允许Bob访问的显式ACE会在任何继承的ACE之前，包括继承拒绝Marketing组访问的ACE。

在访问检查期间，操作系统在到达拒绝Marketing组访问的ACE之前就到达了允许Bob访问的ACE。结果，尽管Bob是Marketing组的成员，他仍然被允许访问该对象。其他Marketing组的成员被拒绝访问。

### 访问控制条目

如前所述，ACL（访问控制列表）是ACE（访问控制条目）的有序列表。每个ACE包含以下内容：

* 用于标识特定用户或组的SID（安全标识符）。
* 指定访问权限的访问掩码。
* 一组位标志，确定子对象是否可以继承该ACE。
* 指示ACE类型的标志。

ACE在本质上是相似的。它们的区别在于它们对继承和对象访问提供的控制程度。有两种类型的ACE：

* 通用类型，附加到所有可安全对象。
* 对于Active Directory对象的ACL中才能出现的特定对象类型。

### 通用ACE

通用ACE对可以继承它们的子对象类型的控制有限。基本上，它们只能区分容器和非容器之间的区别。

例如，在NTFS的文件夹对象上的DACL（自由访问控制列表）可以包括一个通用ACE，允许一组用户列出文件夹的内容。因为列出文件夹的内容是只能在容器对象上执行的操作，所以允许该操作的ACE可以被标记为CONTAINER\_INHERIT\_ACE。只有文件夹中的容器对象（即其他文件夹对象）继承父对象的ACE。非容器对象（即文件对象）不继承父对象的ACE。

通用ACE适用于整个对象。如果通用ACE给了特定用户读取权限，该用户可以读取与对象关联的所有信息，包括数据和属性。对于大多数对象类型来说，这不是一个严重的限制。例如，文件对象只有少数属性，这些属性都用于描述对象的特性，而不是存储信息。文件对象中的大部分信息都存储为对象数据；因此，对文件属性进行单独控制的需求很小。

### 特定对象ACE

特定对象ACE对可以继承它们的子对象类型提供了更高程度的控制。

例如，OU（组织单位）对象的ACL可以有一个特定对象ACE，只标记为User对象继承。其他类型的对象，如计算机对象，将不会继承该ACE。

这就是为什么特定对象ACE被称为特定对象的原因。它们的继承可以限制在特定类型的子对象上。

这两种类别的ACE类型在控制对对象的访问方面有类似的差异。

特定对象ACE可以应用于对象的任何单个属性或该对象的一组属性。这种类型的ACE仅在Active Directory对象的ACL中使用，与其他对象类型不同，Active Directory对象将大部分信息存储在属性中。通常希望对Active Directory对象的每个属性都放置独立的控制，而特定对象ACE使这成为可能。

例如，当您为User对象定义权限时，可以使用一个特定对象ACE允许Principal Self（即用户）对Phone-Home-Primary（homePhone）属性进行写访问，并使用其他特定对象ACE拒绝Principal Self对Logon-Hours（logonHours）属性和设置用户帐户限制的其他属性的访问。

下表显示了每个ACE的布局。
### 访问控制项布局

| ACE字段    | 描述                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 类型        | 表示ACE类型的标志。Windows 2000和Windows Server 2003支持六种类型的ACE：附加到所有可安全对象的三种通用ACE类型。可能出现在Active Directory对象中的三种特定对象ACE类型。                                                                                                                                                                                                                                                                                                                                 |
| 标志        | 一组位标志，用于控制继承和审核。                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| 大小        | 为ACE分配的内存字节数。                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| 访问掩码    | 32位值，其位对应于对象的访问权限。位可以设置为打开或关闭，但设置的含义取决于ACE类型。例如，如果打开了对应于读取权限的位，并且ACE类型为拒绝，则ACE拒绝读取对象的权限。如果相同的位被设置为打开，但ACE类型为允许，则ACE授予读取对象权限的权利。访问掩码的更多详细信息请参见下表。                                                                                                                                                                                                                          |
| SID         | 标识由此ACE控制或监视其访问权限的用户或组。                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |

### 访问掩码布局

| 位（范围） | 含义                               | 描述/示例                                 |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | 对象特定访问权限                   | 读取数据，执行，追加数据                   |
| 16 - 22     | 标准访问权限                       | 删除，写ACL，写所有者                      |
| 23          | 可访问安全ACL                      |                                           |
| 24 - 27     | 保留                               |                                           |
| 28          | 通用ALL（读取，写入，执行）         | 以下所有内容                               |
| 29          | 通用执行                           | 执行程序所需的所有内容                     |
| 30          | 通用写入                           | 写入文件所需的所有内容                     |
| 31          | 通用读取                           | 读取文件所需的所有内容                     |

## 参考资料

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得最新版本的PEASS或下载PDF格式的HackTricks吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，使用全球**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
