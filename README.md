# 密记

单人网页加密记事本。打开已部署的 Cloudflare Worker 网址即可使用。Worker 提供网页、门禁和同步 API，D1 保存带版本号的密文。笔记在浏览器中加密和解密。

## Cloudflare 官方一键部署

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https%3A%2F%2Fgithub.com%2Fbqbfanglian%2FCFE2E-Note)

1. 点击按钮，登录 Cloudflare，选择账户和 GitHub 账户。Cloudflare 会从模板创建新仓库，并在所选账户创建 Worker 和 D1，绑定名为 `DB`。[官方部署按钮文档](https://developers.cloudflare.com/workers/platform/deploy-buttons/)
2. 填写门禁 Secret `APP_PASSWORD`，使用至少 32 个随机字符。若部署页未显示此项，部署后到 **Workers & Pages → 你的 Worker → Settings → Variables and Secrets → Add**，类型选 **Secret**，保存后部署。[Secret 设置指南](https://developers.cloudflare.com/workers/configuration/secrets/#via-the-dashboard)
3. 点击 **Deploy**。高级设置中构建命令可留空，部署命令使用 `npm run deploy`。部署完成后，从 Worker 的 **Overview** 打开 HTTPS 网址。首页直接显示密记登录页面。

### 更新已有 Worker

在该 Worker 的 **Settings → Builds** 确认构建连接的仓库已更新到网页版，并重新部署。保留原 Worker、域名和 D1。在这个 Worker 的部署仓库中确认 `wrangler.jsonc` 的 `DB` 绑定仍指向原来的数据库 UUID。自动建表只补齐缺失的表，已有密文可以用原主密码解锁。

## 使用记事本

在隐私浏览器打开已部署的 HTTPS 网址。输入门禁密码登录，第一次成功登录会初始化数据库表。下一步输入独立的加密主密码，创建或解锁保险库。新建或修改笔记后，点 **加密保存**。

首次创建时，使用专门生成的长随机主密码，或者至少八个独立随机抽取的 Diceware 单词。忘记主密码就无法解密。更换 Cloudflare Secret `APP_PASSWORD` 会使旧门禁会话失效，已有笔记继续使用原加密主密码。

锁定、切换标签页、离开窗口、离开页面或 60 秒无操作会清除页面内的密码输入、明文、密钥和会话，并中止页面在途操作。未保存的草稿一同清除。同步服务已收到的密文写入仍可能完成。

## 隐私与边界

- 页面用主密码在浏览器进程中派生不可导出的 Web Crypto 密钥。登录请求发送门禁密码，同步请求发送短期会话和密文。网页和 API 均使用 `Cache-Control: no-store`。应用只在页面内存中保留会话，并禁用应用侧的浏览器持久化。
- 标题、正文、标签、修改时间和条数都在密文内。密文填充隐藏精确明文长度，服务器仍可观察大小区间和更新次数。
- Worker 分发加密网页。如果有人能篡改部署或下发的网页代码，就可能在解锁时读到主密码和明文。Cloudflare 还会处理门禁密码、连接出口 IP 和请求时间。禁用应用日志和追踪仅影响本项目的可观测性。Mullvad Browser 隐私模式本身不会隐藏 IP。[Mullvad Browser 官方说明](https://mullvad.net/en/help/tag/mullvad-browser)
- 同步服务可删除密文或重放旧的有效密文。已解锁的设备、系统入侵、恶意扩展、键盘记录和系统内存取证都超出应用的保护范围。[EFF 设备加密说明](https://www.eff.org/files/2017/03/09/digital-privacy-border-2017-guide.pdf)

<details>
<summary>开发调试</summary>

把 `.dev.vars.example` 复制为 `.dev.vars`，设置仅用于测试的门禁密码。

```sh
npm ci
npm run dev
npm test
```

测试网页由 Wrangler 提供，默认地址为 `http://127.0.0.1:8787/`。

</details>
