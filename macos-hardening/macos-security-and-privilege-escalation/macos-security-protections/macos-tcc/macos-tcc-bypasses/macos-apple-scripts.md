# Scripts da Apple

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Scripts da Apple

É uma linguagem de script usada para automação de tarefas **interagindo com processos remotos**. Torna bastante fácil **solicitar que outros processos executem algumas ações**. **Malwares** podem abusar desses recursos para abusar de funções exportadas por outros processos.\
Por exemplo, um malware poderia **injetar código JS arbitrário em páginas abertas do navegador**. Ou **clicar automaticamente** em algumas permissões solicitadas ao usuário;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Aqui estão alguns exemplos: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Encontre mais informações sobre malware usando scripts da Apple [**aqui**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Os scripts da Apple podem ser facilmente "**compilados**". Essas versões podem ser facilmente "**descompiladas**" com `osadecompile`

No entanto, esses scripts também podem ser **exportados como "Somente leitura"** (através da opção "Exportar..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
E neste caso, o conteúdo não pode ser descompilado mesmo com `osadecompile`.

No entanto, ainda existem algumas ferramentas que podem ser usadas para entender esse tipo de executáveis, [**leia esta pesquisa para mais informações**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). A ferramenta [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) com [**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile) será muito útil para entender como o script funciona.

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
