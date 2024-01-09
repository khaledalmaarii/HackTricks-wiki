<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) é uma ferramenta que pode ser usada com um Raspberry PI ou um Arduino para tentar encontrar os pinos JTAG de um chip desconhecido.\
No **Arduino**, conecte os **pinos de 2 a 11 a 10 pinos potencialmente pertencentes a um JTAG**. Carregue o programa no Arduino e ele tentará forçar bruscamente todos os pinos para descobrir se algum deles pertence ao JTAG e qual é cada um.\
No **Raspberry PI**, você só pode usar **pinos de 1 a 6** (6 pinos, então você irá testar cada pino JTAG potencial mais lentamente).

## Arduino

No Arduino, após conectar os cabos (pino 2 a 11 para pinos JTAG e GND do Arduino para o GND da base), **carregue o programa JTAGenum no Arduino** e no Monitor Serial envie um **`h`** (comando para ajuda) e você deverá ver a ajuda:

![](<../../.gitbook/assets/image (643).png>)

![](<../../.gitbook/assets/image (650).png>)

Configure **"Sem final de linha" e 115200baud**.\
Envie o comando s para iniciar a varredura:

![](<../../.gitbook/assets/image (651) (1) (1) (1).png>)

Se você estiver em contato com um JTAG, encontrará uma ou várias **linhas começando por FOUND!** indicando os pinos do JTAG.


<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
