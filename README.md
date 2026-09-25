# secure-envelope-web

密文信封的密钥版本轮换审阅工具：信封按主密钥版本封存，轮换任务分批重包，
失败项保留原因与重试机会，浏览器审阅页实时反映服务端状态。

## 运行

```sh
npm start          # 监听 4182，状态持久化到 data/keyring.json
PORT=4200 ENVELOPE_DATA_FILE=/tmp/state.json npm start
npm test           # node --test
```

打开 http://localhost:4182 进入审阅页。

## 模型

- **主密钥**：`密钥 ID + 版本`，材料只存服务端；版本可 `active` / `disabled`
  （停用只阻止新的包裹，不影响历史版本解包）。
- **信封**：保存密文摘要与 wrap 版本链；任一时刻恰好一个 `current` wrap，
  新 wrap 只有在完整生成后才会原子替换当前引用，旧的转为 `superseded`。
- **轮换任务**：`from`/`to` 为 `keyId@version` 引用；启动时按源版本圈定信封，
  切成若干批次。条目状态机：
  `pending → processing → succeeded / failed / needs_confirmation`，
  每次转换都带单调序号与来源（批次、重试、确认、策略变更），不依赖时间推断。
- **失败分级**：`target_key_unavailable` 等可自动重试（受 `maxAttempts` 约束）；
  `unwrap_failed`、`source_version_changed` 默认进入人工确认，确认后才能重试。
  重试幂等：已成功的条目重试为空操作，同一信封不会产生多个竞争的当前版本；
  未完成的轮换会阻止针对同一信封的新轮换。
- **解密**：按信封当前 wrap 记录的版本路由解包，历史版本始终可读；
  接口只返回数据密钥摘要，密钥材料与包裹密文不出服务端。

## 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/keys` | 创建主密钥（v1） |
| POST | `/api/keys/:id/versions` | 新增密钥版本 |
| POST | `/api/keys/:id/versions/:v/status` | 启用/停用版本 |
| POST | `/api/envelopes` | 封存信封（用当前版本） |
| GET | `/api/envelopes/:id` | 信封详情（含 wrap 历史指纹） |
| POST | `/api/envelopes/:id/decrypt` | 按当前 wrap 版本解包 |
| POST | `/api/rotations` | 创建轮换（`from`/`to`/`batchSize`/`maxAttempts`） |
| GET | `/api/rotations/:id` | 轮换详情（批次、条目、审计历史） |
| POST | `/api/rotations/:id/batches/:seq/run` | 运行一个批次 |
| POST | `/api/rotations/:id/items/:env/retry` | 重试条目（幂等） |
| POST | `/api/rotations/:id/items/:env/confirm` | 人工确认 |
| PATCH | `/api/rotations/:id/policy` | 修改重试策略 |
| GET | `/api/keyring` | 全量脱敏视图 |

所有响应经 `publicView` 脱敏：不含密钥材料、数据密钥或包裹密文，只有引用、
状态、指纹与审计记录。前端不保存结果数组，切换批次或重新打开页面都会重新
拉取服务端状态，并用单调请求守卫丢弃过期的响应。
