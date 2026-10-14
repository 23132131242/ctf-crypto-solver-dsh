/**
 * dsh-ctf-crypto-solver — 合并版 CTF Crypto 解题 skill 插件
 *
 * 融合两份来源：
 *   · ctf-crypto-solve  —— 铁律 / 七步工作流 / 攻击决策树 / 21 节手法库 / 14 个 crypto_* 工具表
 *   · ctf-crypto-solver —— 授权边界条款 / 十段输出模板 / 4 份专项 references / rsa-triage 脚本
 *
 * 本插件只注册 skill（不注册工具）；算力由同 profile 的 dsh-crypto-lab 提供。
 */
import { readFileSync } from 'node:fs'
import * as nodePath from 'node:path'
import { fileURLToPath } from 'node:url'

export const name = 'dsh-ctf-crypto-solver'
export const inject = ['skills']

const PKG_ROOT = nodePath.dirname(fileURLToPath(import.meta.url))
const SKILL_DIR = nodePath.join(PKG_ROOT, 'skills', 'ctf-crypto-solver')
const SKILL_ID = 'ctf-crypto-solver'

function loadSkill() {
  const raw = readFileSync(nodePath.join(SKILL_DIR, 'SKILL.md'), 'utf8')
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n/u.exec(raw)
  if (!match) throw new Error('dsh-ctf-crypto-solver: invalid SKILL.md frontmatter')
  const declared = /^name:\s*([^\r\n]+)$/mu.exec(match[1])
  const description = /^description:\s*([^\r\n]+)$/mu.exec(match[1])
  if (declared?.[1]?.trim() !== SKILL_ID) {
    throw new Error(`dsh-ctf-crypto-solver: SKILL.md name 必须是 ${SKILL_ID}，实际 ${declared?.[1]?.trim()}`)
  }
  if (!description?.[1]?.trim()) throw new Error('dsh-ctf-crypto-solver: SKILL.md 缺少 description')
  return {
    name: SKILL_ID,
    description: description[1].trim(),
    content:
      raw.slice(match[0].length).trim() +
      '\n\n本 skill 自带 references/ 与 scripts/rsa-triage.mjs（路径见 skill 的 base directory）。' +
      '算力工具来自同 profile 的 dsh-crypto-lab（crypto_parse/crypto_rsa/crypto_ecc/crypto_sym/crypto_copper/crypto_poly/crypto_lattice/crypto_lcg/crypto_mt/crypto_lfsr/crypto_util/crypto_classic/crypto_paillier/crypto_js）。',
    source: 'runtime',
    resourceBase: { kind: 'directory', path: SKILL_DIR }
  }
}

export function apply(ctx) {
  ctx.skills.register(loadSkill())
}
