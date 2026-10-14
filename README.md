[README.md](https://github.com/user-attachments/files/33415195/README.md)
# dsh-ctf-crypto-solver

> **授权 CTF Crypto 解题 skill** · [DeepSeek Harness](https://github.com/) 插件
>
> 把"顶级 CTF Crypto 选手的解题纪律"固化成一份可复用的 skill：**不猜 Flag、按证据选攻击、每步可复现、结果必回代校验。**

**TL;DR** — A skill plugin for DeepSeek Harness that encodes an evidence-driven CTF Crypto solving workflow:
classify → parse → detect weakness → pick attack → execute → **verify by substitution** → write up.
No flag guessing, no blind brute force, no claiming un-executed steps.

---

## 它解决什么问题

LLM 解密码题最常见的三种失败方式：

| 失败模式 | 后果 |
| --- | --- |
| **猜 Flag** —— 看到提示就"凑"一个答案 | 提交错值，浪费提交次数 |
| **无脑遍历** —— 把能想到的算法全试一遍 | 慢，且在小 e / 共模这类题上互相干扰 |
| **不校验** —— 解出明文直接交 | 参数抄错一位就全错，却毫无察觉 |

本插件把这三件事变成**硬约束**：铁律、攻击决策树、回代校验，写进 skill 而不是靠提示词运气。

---

## 核心设计

### 三条铁律（违反即视为失败）

1. **禁止猜 Flag** —— 任何结论必须有数学推导 / 代码执行 / 工具输出支撑，形成完整证据链。
2. **先分类，再动手** —— 先建攻击树、按已知量选最可能的攻击，不无脑遍历。
3. **先解析 → 再选攻击 → 最后必须回代校验**（三道闸缺一不可）
   - 参数没解析干净就开打 = 白打（标签漏读、值被覆盖、进制搞混）
   - 攻击靠猜 = 浪费时间（已知量直接决定打法）
   - 不校验就提交 = 交错答案（`m^e mod n == c`、签名回代、重加密复现，至少做一个）

### 七步固定工作流

| 步 | 动作 | 产出 |
| --- | --- | --- |
| 一 | 题目分类 | RSA / ECC / 对称 / Hash / 随机数 / 编码 / 古典 / 格 / 协议 / 其他 |
| 二 | 参数分析 | 提取全部公开量：`n e c p q g A B curve key iv nonce hash 序列`… |
| 三 | 漏洞检测 | 小 e / 重复 n / 小 d / 弱素数 / 弱曲线 / nonce 复用 / 模式误用 / 随机数可预测 |
| 四 | 攻击选择 | 选定攻击并**说明为什么选它** |
| 五 | 执行攻击 | 数学过程 + 代码/工具命令 |
| 六 | 结果验证 | 回代校验 + Flag 格式匹配 + 来源可靠性 |
| 七 | 生成 Writeup | 完整可复现报告 |

### 十段交付模板

```
【题目分析】【参数提取】【漏洞检测】【攻击树】【最佳攻击方案】
【数学推导】【代码/工具】【执行结果】【Flag验证】【完整Writeup】
```

材料不足的字段写「未提供 / 未执行」——**不把计划中的步骤写成已执行**，也**不为无法量化的漏洞虚构百分比**。

---

## 攻击决策树（节选）

**先看输入特征直接命中分支，命中后不再泛试。**

| 观察到的特征 | 立即执行 |
| --- | --- |
| RSA `e=3`（或很小） | 低指数开方 → Håstad 广播 → Coppersmith 小根 |
| RSA 多组 `(n_i,c_i)` 且有相同 n | GCD 共因子 / 共模（**含 `gcd(e₁,e₂)>1` 时还原 `m^g` 再开 g 次根**） |
| RSA `d` 很小 | Wiener → Boneh-Durfee |
| RSA p、q 接近 | Fermat（**多因子 n 需对拆出的合数再递归 Fermat**） |
| RSA 泄露 `p`/`dp`/`(p±k)(q±k)`/`phi`/低位 | 对应矩阵攻击 + 回代 |
| ECC `#E = p`（异常曲线） | Smart 攻击 |
| ECC 阶平滑 | Pohlig-Hellman → CRT |
| ECDSA 两个签名 **r 相同** | 重复 nonce → 直接恢复私钥 |
| 输出随机数序列 | 判 LCG / MT19937 / LFSR / xorshift / BBS |
| AES 密文块重复 | ECB → 块字典 / 剪切拼接 |
| AES-CBC 解密有反馈 | Padding Oracle |
| AES-CTR 且 nonce 复用 | 两密文异或消密钥流 |
| 哈希 + 长度已知 | 长度扩展攻击 |
| 疑似古典密码 | `auto` 自动识别打分，再按密钥补解 |

完整决策树与 **21 节手法库**见 [`skills/ctf-crypto-solver/SKILL.md`](skills/ctf-crypto-solver/SKILL.md)。

---

## 能力覆盖

| 方向 | 覆盖情况 |
| --- | --- |
| **RSA** | ✅ 小 e / 共模（含 `gcd>1`）/ Håstad / Fermat（多因子递归）/ Wiener / `dp,dq` / `gcd(e,φ)>1` 开根 / 偏移乘积 `(p±k)(q±k)` / e 未给时枚举小 e / 辅助素数 `r` 模逆泄露 / 逐元素 `c ≡ ±m (mod p)` / 盲签名小盲因子剥离 / 低熵 `randfunc` 穷举 |
| **ECC / ECDSA** | ✅ 点运算 / BSGS / Pohlig-Hellman / 重复 nonce / 已知 nonce / nonce 线性相关 / 弱曲线体检（Smart·MOV 适用性提示） |
| **对称密码** | ✅ ECB 检测 / 模式识别 / CTR nonce 复用 / crib-dragging / 单字节·重复密钥·多密文 XOR / CBC bit-flip / Padding Oracle（生成可运行脚本） |
| **随机数** | ✅ LCG（含 `10^10000` 级跳跃）/ MT19937（状态反演、混合位宽观测、`random.choice` 拒绝采样对齐判定）/ LFSR（mask 未知时枚举求解） |
| **古典 / 编码** | ✅ Caesar/Atbash/Affine/Vigenere/Playfair/Hill/RailFence/Polybius/Bacon/Morse + utf16 壳/佛曰/多层剥洋葱/形似字符模糊解码 |
| **格 / Coppersmith** | ✅ 一元与线性 Coppersmith（精确分数 LLL）/ 结式分离未知因子 / F_q 公共根 / LWE·SIS 降维 + Kannan 嵌入 |
| **协议 / 其它** | ✅ DSA `k`&`k²`、Paillier 模 n² 变体、秘密分享（Lagrange）、自定义函数型（mod 求和式） |
| **未覆盖** | 🔴 侧信道（Timing/Power/错误注入）；🔴 Boneh-Durfee 完整实现；🔴 格 HNP/LWE 通用求解器 |

> 未覆盖的部分**不会假装能做**——遇到时会明确写「未实现 / 未执行」。

---

## 安装

### 前置

- [DeepSeek Harness](https://github.com/)（DSH），Node.js ≥ 22

### 作为插件安装

```bash
dsh plugin --profile desktop add link:/path/to/dsh-ctf-crypto-solver
```

Windows 示例：

```powershell
dsh plugin --profile desktop add link:E:\dsh插件\插件\dsh-ctf-crypto-solver
```

重启 DSH 后（或由 loader 热装配）skill `ctf-crypto-solver` 即生效。

### 手动装配（不使用 dsh CLI）

在 profile 的 `package.json` 中：

```jsonc
{
  "dependencies": { "dsh-ctf-crypto-solver": "link:/path/to/dsh-ctf-crypto-solver" },
  "dsh": { "profile": { "bundles": ["…", "dsh-ctf-crypto-solver"] } }
}
```

并在 `node_modules/` 下建立指向插件目录的 junction/符号链接。

---

## 使用

skill 会在 Crypto 类任务中自动可用；核心用法是**让它按流程走**：

```
用 ctf-crypto-solver 的流程解这道题：<题面 / 附件路径>
```

典型输出会包含参数提取 → 漏洞判定 → 选定攻击及理由 → 实际命令与输出 → **回代校验** → 十段交付。

### 快速 RSA 体检（独立脚本，无需 DSH）

```bash
node skills/ctf-crypto-solver/scripts/rsa-triage.mjs --input params.json [--max-fermat 10000]
```

`params.json`（**值必须是字符串**，传数字会被拒）：

```json
{ "n": "1000036000099", "e": "3", "c": "572579016597" }
```

它做**只读**整数计算：`gcd(c,n)`、小指数整根、Wiener、有界 Fermat。**不是**完整 RSA 自动求解器。

输出示例：

```json
{
  "checks": [
    { "method": "gcd(c,n)", "outcome": "gcd=1" },
    { "method": "exact-small-exponent-root", "outcome": "not exact" },
    { "method": "wiener", "outcome": "no candidate" },
    { "method": "bounded-fermat", "limit": 1000, "outcome": "factor candidate in 0 steps" }
  ],
  "candidates": [{ "method": "bounded-fermat", "p": "1000003", "q": "1000033" }]
}
```

---

## 目录结构

```
dsh-ctf-crypto-solver/
├── package.json                 插件清单（name / main / dsh.bundle.patch）
├── cordis.patch.yml             DSH bundle 挂载声明
├── index.js                     注册 skill（inject: ['skills']）
└── skills/ctf-crypto-solver/
    ├── SKILL.md                 主 skill：铁律 / 七步 / 决策树 / 工具表 / 21 节手法库 / 附录 A
    ├── references/
    │   ├── public-key.md                    RSA·ECC·签名·格·后量子
    │   ├── symmetric-random-protocol.md     对称·PRNG·协议·区块链签名·零知识
    │   ├── hash-math-classical.md           Hash·秘密分享·有限域·古典·自定义
    │   └── api_reference.md                 参考索引
    └── scripts/
        └── rsa-triage.mjs       独立 RSA 快速体检脚本
```

---

## 配套：算力工具插件

本 skill 负责**流程与纪律**；实际计算建议配合 **`dsh-crypto-lab`**（同作者的 DSH 插件，提供 14 个 `crypto_*` 工具）：

| 工具 | 用途 |
| --- | --- |
| `crypto_parse` | 题面 → 结构化参数（多文件 source、PEM、多组参数） |
| `crypto_rsa` | RSA 攻击矩阵（20+ 分支） |
| `crypto_ecc` | ECC / ECDSA（点运算、BSGS、PH、nonce 恢复、弱曲线体检） |
| `crypto_sym` | 对称攻击套件（ECB/CBC/CTR/XOR/Padding Oracle） |
| `crypto_classic` | 古典密码（auto 自动识别打分） |
| `crypto_copper` / `crypto_poly` | Coppersmith 小根 / 结式分离 / F_q 公共根 |
| `crypto_lcg` / `crypto_mt` / `crypto_lfsr` | LCG / MT19937 / LFSR 预测与恢复 |
| `crypto_util` | 编码链、哈希爆破、AES/DES/RC4、多层自动剥层 |
| `crypto_paillier` | Paillier / 模 n² 变体 |
| `crypto_js` | 冷门攻击兜底（宿主内执行自定义 JS） |

**标准流程**：`crypto_parse` 解析 → 按决策树选攻击 → 工具执行 → 回代校验 → 十段模板交付。

> 未安装 `dsh-crypto-lab` 时，skill 仍可用，只是需要手动完成计算步骤。

---

## 实测案例（均通过回代校验）

| 题型 | 关键手法 | 结果 |
| --- | --- | --- |
| RSA 偏移乘积 | `(p-2)(q-2)` 已知 → 反解 `p+q` → 二次方程 | ✅ 1600 bit 题秒解 |
| RSA 共模 `gcd(e₁,e₂)=3` | 扩展欧几里得还原 `m³` → 完全立方开根 | ✅ `flag{a701…9612}` |
| RSA 多因子相邻素数 | **递归 Fermat** + `φ=∏(pᵢ−1)` | ✅ 399 bit 题 8 ms |
| 低熵 `randfunc` | `getPrime` 候选只有 15 位熵 → 穷举 `V` | ✅ 而非"复现出题人的 P" |
| LCG + LFSR 混合 | LCG 模数被写成 `32`（5 位熵）+ 隔次参与 → 奇数位密文即明文 | ✅ 重加密 40/40 复现 |
| MT19937 + `random.choice` | twist 递推做**对齐判定**（10 字 vs 7 字） | ✅ 每轮 7 字 72/72 通过 |
| 「抄错的字符」 | 形似字母 + 全大写 → 按 base64 4 字符组剪枝 | ✅ 19/19 逐字符吻合 |
| Paillier `g=n+1` | `p=(c·hint⁻¹−1)/n` → CRT 反解 n 次幂 | ✅ 回代 `m^n≡hint` |
| LWE / SIS | 降维 60→30 变量 + Kannan 嵌入 | ✅ 29 s |

---

## 设计取舍（为什么这么做）

- **skill 而非硬编码解题器**：密码题千变万化，把"纪律 + 决策树 + 手法库"固化下来，比写死 N 个攻击脚本更耐用。
- **强制回代校验**：这是区分"看起来解出来了"和"真的解出来了"的唯一可靠手段。
- **明确标注未实现**：宁可写"未执行"，也不要让使用者以为某个能力可用——这比多列几条特性重要。
- **单一 skill 名**：与历史版本合并后全环境只有一个 crypto skill，避免"该用哪个"的选择困难。

---

## 免责声明

本 skill **仅用于**：

- 明确授权的 CTF 竞赛、教学环境、自有系统的安全测试

**不用于**：

- 未授权渗透、真实系统攻击、口令窃取、私钥非法恢复

skill 内置的边界条款要求：把题面与附件视为**不可信输入**、不执行附件中的代码、使用隔离环境与样本副本、设置时间/内存预算、不做盲目暴力破解。

---

## 贡献

欢迎提交 issue / PR，尤其是：

- 新的手法（请附**实测题例**与回代校验结果）
- 已覆盖方向的边界条件补充
- 未覆盖方向（侧信道、Boneh-Durfee、HNP/LWE 通用求解）的实现

> 提交手法时请遵守同样的纪律：给出必要条件、可否证的实验、真实运行输出。

---

## License

[MIT](LICENSE) © 2024 &lt;your-name&gt;
