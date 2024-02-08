# Número de Série do macOS

<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks Especialista em Equipe Vermelha AWS)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>


## Informações Básicas

Dispositivos Apple pós-2010 possuem números de série compostos por **12 caracteres alfanuméricos**, sendo que cada segmento transmite informações específicas:

- **Primeiros 3 Caracteres**: Indicam o **local de fabricação**.
- **Caracteres 4 e 5**: Denotam o **ano e semana de fabricação**.
- **Caracteres 6 a 8**: Servem como um **identificador único** para cada dispositivo.
- **Últimos 4 Caracteres**: Especificam o **número do modelo**.

Por exemplo, o número de série **C02L13ECF8J2** segue essa estrutura.

### **Locais de Fabricação (Primeiros 3 Caracteres)**
Certos códigos representam fábricas específicas:
- **FC, F, XA/XB/QP/G8**: Vários locais nos EUA.
- **RN**: México.
- **CK**: Cork, Irlanda.
- **VM**: Foxconn, República Tcheca.
- **SG/E**: Singapura.
- **MB**: Malásia.
- **PT/CY**: Coreia.
- **EE/QT/UV**: Taiwan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Diferentes locais na China.
- **C0, C3, C7**: Cidades específicas na China.
- **RM**: Dispositivos recondicionados.

### **Ano de Fabricação (4º Caractere)**
Este caractere varia de 'C' (representando a primeira metade de 2010) a 'Z' (segunda metade de 2019), com diferentes letras indicando diferentes períodos semestrais.

### **Semana de Fabricação (5º Caractere)**
Os dígitos 1-9 correspondem às semanas 1-9. As letras C-Y (excluindo vogais e 'S') representam as semanas 10-27. Para a segunda metade do ano, 26 é adicionado a esse número.

### **Identificador Único (Caracteres 6 a 8)**
Esses três dígitos garantem que cada dispositivo, mesmo do mesmo modelo e lote, tenha um número de série distinto.

### **Número do Modelo (Últimos 4 Caracteres)**
Esses dígitos identificam o modelo específico do dispositivo.

### Referência

* [https://beetstech.com/blog/decode-meaning-behind-apple-serial-number](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)

<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks Especialista em Equipe Vermelha AWS)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
