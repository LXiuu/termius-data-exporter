# Termius 数据导出器

本项目是一个 Termius 本地数据导出工具，已在当前最新版本 Termius 9.38.1 测试，可以从当前 Termius 本地数据库中导出主机、账号密码，生成 Termius 导入模板可用的 CSV。

## 参考与说明

本仓库的实现思路参考了 [ZacharyZcR/termius-exporter](https://github.com/ZacharyZcR/termius-exporter)。原项目已经较长时间未更新，已不适用于当前最新版本 Termius 9.38.1 的本地数据结构和导入模板，因此本仓库围绕当前最新版本重新开发。

## 功能特性

- 导出当前 Termius 主机列表中的主机、账号密码。
- 生成 Termius 导入模板可用的 CSV，方便备份或迁移数据。
- 主机和密码按 Termius 当前关联关系匹配，尽量避免历史连接记录或已删除主机混入导出结果。
- 支持常见的本地数据结构差异，提升主机、用户名和密码的配对成功率。
- 提供脱敏诊断命令，方便排查空密码原因，但不会在报告里输出明文密码。

## 当前导出格式

`termius_import.csv` 按 Termius 导入模板输出：

```csv
Groups,Label,Tags,Hostname/IP,Protocol,Port,Username,Password
```

## 使用方式

```bash
npm install
node termius-exporter.js
```



## 诊断命令

诊断报告会脱敏，不输出明文密码：

```bash
node termius-exporter.js --blank-report
node termius-exporter.js --identity-report
node termius-exporter.js --schema-report
node termius-exporter.js --field-report
```

`--blank-report` 常见原因：

- `missingIdentity`：主机有 SSH 配置，但当前数据里没有关联到可用 identity。
- `missingSshConfig`：当前主机记录没有暴露 SSH 配置关联。
- `missingFieldCredential`：字段级主机存在，但当前数据库里没有可配对的 `username/password` 字段。
- `fieldHostDefinitions`：导出源来自单字段加密块重建，通常表示 Termius 没有给出完整 JSON hostDefinition。
