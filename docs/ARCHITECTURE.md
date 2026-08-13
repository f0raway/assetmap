# 代码模块结构

项目以命令行为入口，以 SQLite 任务数据为阶段间唯一事实来源。`data/` 下的扫描输出、审计 JSON 和截图都是可再生的交付证据，而不是阶段之间的唯一传递媒介。

```text
assetmap/
  cli/                 命令层：参数解析、兼容命令与交付编排
  stages/              可独立执行的生产阶段与统一阶段编排器
  collectors/          外部企业与备案数据采集器
  services/
    acquisition/       企业发现、手工资产导入与交互录入
    mapping/           子域名、DNS、FOFA 与端口发现
    identification/    服务分类、Web 探测、截图与 AI 分析
    delivery/          数据导出、报告、质量门禁与交付打包
    operations/        状态、复核、缺口补全与数据维护
    runtime/           配置向导、环境检查、工具安装与定位
  config.py            配置模型与 YAML 读写
  db.py                SQLite 引擎与表初始化
  models.py            各模块共享的持久化模型
```

## 依赖方向

`cli -> stages -> services -> config/db/models` 是主依赖方向。每个 `stages/*` 模块只负责打开会话、调用一个生产服务并提供 `python -m` 入口；`stages/pipeline.py` 只调用这些阶段的公开 `run()` 函数。服务模块可依赖同层的基础适配器（例如 FOFA、AI 客户端、工具定位器），但不应反向依赖 CLI。交付和运营模块从数据库汇总已有结果，不重新执行外部扫描。

## 主流水线

`acquisition -> mapping -> identification -> delivery`：

1. 企业发现或人工导入写入公司与资产数据。
2. 子域名/DNS 和端口模块产出可验证的网络证据。
3. 服务/Web/AI 模块把网络证据转为服务与页面识别结果。
4. 报告、质量和交付模块从数据库生成可交付文件。
5. 运营模块把质量缺口变成复核工作单和下一轮补全动作。

## 阶段编排

统一编排器按以下顺序执行，并以 SQLite 中的任务状态决定跳过、续跑或刷新后续阶段：

1. `enterprise-discovery`
2. `domain-mapping`
3. `port-discovery`
4. `service-identification`
5. `web-identification`
6. `report-generation`

`assetmap pipeline` 是明确的统一入口；`assetmap run` 为兼容命令，但也委托给同一个编排器。各阶段可用 `python -m assetmap.stages.<stage_name>` 单独调试，读写的始终是同一任务数据库。

## 目录边界

- `assetmap/`：可发布的应用源码。`collectors/` 只放外部数据源适配器；`services/` 放可复用业务能力；`stages/` 放可独立执行的流程环节；`cli/` 与 `web/` 仅负责用户入口。
- `config.example.yaml`、`config/subfinder/provider-config.example.yaml`：可提交的配置样例。真实 `config.yaml` 和 Provider Key 文件仅保留在本机。
- `data/`、`reports/`、`deliveries/`、`tools/`：本机运行数据、交付物和外部工具，均不属于源码包，也不应提交到仓库。
- `tests/`：按服务或阶段命名的自动化验证；新增业务模块必须在这里增加相同边界的测试。
