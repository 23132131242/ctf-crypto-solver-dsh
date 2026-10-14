# 公钥、签名与格分析

## RSA 路线图

- 首检：记录 `n,e,c` 的进制/位长与分组关系；检查 `0 <= c < n`、`gcd(c,n)`、重复模数/共享素因子、素数生成提示。多模数时先做成对/批量 GCD；再判断 n 是否与已知整数存在结构关系。
- 分解：对“p 与 q 接近”用有界 Fermat；对明显小因子用试除/Pollard Rho；`p-1` 平滑才考虑 Pollard p-1；ECM、msieve、yafu 等昂贵算法应先估算可行性。获得 p,q 后核对乘积、求 φ(n)、校验 `gcd(e,φ)=1`，最后用 `d=e^-1 mod φ` 并重加密确认。
- 小指数/消息关系：不带填充且 `m^e<n` 时做精确整根；Håstad 需足够多相同明文、互素模数；Common Modulus 需同 n、同 m 且 `gcd(e1,e2)=1`（负指数需可逆）。Franklin-Reiter 需同模数、同指数及已知仿射关系。相关消息或部分泄露用多项式建模后才考虑 Coppersmith/Howgrave-Graham。
- 私钥异常：Wiener 适用于非常小的 d，试连分数并验证候选 p,q；Boneh-Durfee 与 Partial Key Exposure 需满足明确位长与已知位约束。Padding 题先确认 PKCS#1 v1.5/OAEP、错误回显和 oracle 行为，再评估漏洞，不假定纯数学模型适用。
- 结果验证：因子乘积、解密/重加密、填充去除与文本编码应逐项独立核对。第三方因子库只查询公开挑战整数且取得用户同意后再用。

自带基础脚本：输入 JSON 例子 `{"n":"3233","e":"17","c":"855"}`，命令 `node scripts/rsa-triage.mjs --input sample.json --max-fermat 10000`。只读本地文件，不依赖网络；最大迭代 100000。对候选因子与明文必须在报告中复核，不可将脚本候选作为最终 Flag。

## ECC/ECDSA

- 核对域 `p` 或 `GF(2^m)`、曲线方程、基点 G、阶 n、余因子 h、公钥点是否在曲线上和签名中的 `r,s,z`（z 的截断规则按方案确定）。
- 离散对数：只有群阶小或平滑时考虑 BSGS、Pollard rho、Pohlig-Hellman；MOV 要求低嵌入度；Smart 需满足 anomalous 条件（如 `#E(Fp)=p`）。Invalid Curve/Twist/小子群路径需可控输入点且有未验证点的授权挑战实现，不对现实服务试探。
- ECDSA 复用 nonce：同一私钥、相同 r 且签名方程一致时由 `s_i = k^-1(z_i+r d) mod n` 解 k,d，并以 `dG=Q`、签名验证和各消息摘要核对。部分 nonce 泄露要建 Hidden Number Problem，明确泄漏位数/噪声/样本量后再采用 LLL/BKZ，不能把算法名当作成功证明。

## 格与后量子

- 写明目标格基、维度、行列约定、缩放、目标向量、det 与求解界；区分 SVP、CVP、LLL 近似与 BKZ 参数。RSA Coppersmith、HNP、部分私钥/明文恢复均要求清楚的小根界与一致的模方程。
- 对 LWE/Ring-LWE/NTRU/后量子题先核对模数 q、维度、噪声、样本数、环结构与泄漏模型；仅在违反安全参数或实现缺陷时尝试攻击。SageMath/fpylll/z3 是按需工具，先检测可用性、保留版本和随机种子，结果须代入原方程复验。