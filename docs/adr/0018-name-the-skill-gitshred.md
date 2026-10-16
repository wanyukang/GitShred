# 将 skill 命名为 GitShred

这个 skill 命名为 GitShred。名称可以保持产品化和易记，但文档与行为边界必须明确：GitShred 只处理 Git 历史中的泄露凭据处置，不是通用 Git 清理器、仓库瘦身工具或 BFG 命令封装。

## 考虑过的方案

- git-credential-remediation：语义精确，但更像流程名称，产品感弱。
- git-secret-remediation：语义接近，但 secret 的范围容易扩展到 PII 或业务机密。
- GitShred：名字简洁，但必须靠文档约束范围，避免被误解为通用清理工具。

## 后果

- SKILL.md 的描述必须直接说明 GitShred 的范围是泄露凭据处置。
- 触发规则不能因为名字里的 shred 而接受仓库瘦身或大文件清理请求。
- BFG 仍只是第一版执行后端，不是 GitShred 的领域中心。
