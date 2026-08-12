"""配置和环境相关命令"""

from __future__ import annotations

from pathlib import Path

import httpx
import typer

from assetmap.config import DEFAULT_CONFIG_PATH, load_config, write_sample_config
from assetmap.db import create_db_and_engine
from assetmap.services.runtime.environment import EnvironmentCheckService
from assetmap.services.identification.ai_client import chat_completion
from assetmap.services.acquisition.manual_import import write_manual_asset_template


def register(app: typer.Typer) -> None:
    @app.command("init")
    def init_command(
        config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
        force: bool = typer.Option(False, "--force"),
    ):
        config_exists = config_path.exists()
        path = write_sample_config(config_path, overwrite=force)
        manual_template = write_manual_asset_template()
        config = load_config(path)
        create_db_and_engine(config.database.url)
        if config_exists and not force:
            typer.echo(f"Config exists, kept unchanged: {path}")
        else:
            typer.echo(f"Initialized config: {path}")
        typer.echo(f"Initialized manual asset template: {manual_template}")
        typer.echo(f"Initialized database: {config.database.url}")

    @app.command("configure")
    def configure_command(
        config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
    ):
        """TUI 配置向导：逐项配置 config.yaml"""
        from assetmap.services.runtime.config_wizard import ConfigWizardService

        service = ConfigWizardService(progress=typer.echo)
        success = service.run(config_path)
        if not success:
            raise typer.Exit(1)

    @app.command("install-tools")
    def install_tools_command(
        tools: list[str] | None = typer.Argument(None, help="要安装的工具列表，默认全部安装"),
        tools_dir: Path = typer.Option(Path("tools"), "--tools-dir", help="工具安装目录"),
    ):
        """安装外部工具：subfinder, dnsx, nmap"""
        from assetmap.services.runtime.tool_install import ToolInstallService

        service = ToolInstallService(tools_dir=tools_dir, progress=typer.echo)
        success = service.run(tools)
        if not success:
            raise typer.Exit(1)

    @app.command("env-check")
    def env_check_command(config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config")):
        """检查环境依赖是否就绪"""
        config = load_config(config_path)
        results = EnvironmentCheckService(config).check()

        typer.echo("")
        typer.echo("=" * 50)
        typer.echo("  环境检查")
        typer.echo("=" * 50)
        typer.echo("")

        # 分类显示结果
        categories = {
            "python": [],
            "browser": [],
            "tool": [],
            "file": [],
            "config": [],
        }

        for result in results:
            name = result["name"]
            if name.startswith("python:"):
                categories["python"].append(result)
            elif name.startswith("browser"):
                categories["browser"].append(result)
            elif name in ("subfinder", "dnsx", "nmap"):
                categories["tool"].append(result)
            elif name in ("enscan.script", "tools.wordlist"):
                categories["file"].append(result)
            else:
                categories["config"].append(result)

        # Python 依赖
        typer.echo("Python 依赖")
        all_python_ok = all(r["ok"] for r in categories["python"])
        if all_python_ok:
            typer.echo("  ✓ 全部已安装")
        else:
            for r in categories["python"]:
                if not r["ok"]:
                    typer.echo(f"  ✗ {r['name']}: {r['detail']}")
                    typer.echo(f"    → {r['suggestion']}")
        typer.echo("")

        # 浏览器
        typer.echo("浏览器")
        for r in categories["browser"]:
            status = "✓" if r["ok"] else "✗"
            typer.echo(f"  {status} {r['name']}: {r['detail']}")
            if not r["ok"] and r["suggestion"]:
                typer.echo(f"    → {r['suggestion']}")
        typer.echo("")

        # 外部工具
        typer.echo("外部工具")
        for r in categories["tool"]:
            status = "✓" if r["ok"] else "✗"
            typer.echo(f"  {status} {r['name']}: {r['detail']}")
            if not r["ok"] and r["suggestion"]:
                typer.echo(f"    → {r['suggestion']}")
        typer.echo("")

        # 配置文件
        typer.echo("配置文件")
        for r in categories["file"]:
            status = "✓" if r["ok"] else "✗"
            typer.echo(f"  {status} {r['name']}: {r['detail']}")
            if not r["ok"] and r["suggestion"]:
                typer.echo(f"    → {r['suggestion']}")
        typer.echo("")

        # API 配置
        typer.echo("API 配置")
        for r in categories["config"]:
            status = "✓" if r["ok"] else "✗"
            typer.echo(f"  {status} {r['name']}: {r['detail']}")
            if not r["ok"] and r["suggestion"]:
                typer.echo(f"    → {r['suggestion']}")
        typer.echo("")

        # 总结
        all_ok = all(r["ok"] for r in results)
        typer.echo("─" * 50)
        if all_ok:
            typer.echo("  ✓ 所有依赖就绪，可以开始使用!")
            typer.echo("")
            typer.echo("  下一步: assetmap scan \"公司名称\"")
        else:
            typer.echo("  ✗ 依赖不完整，请安装缺失项后重新检查")
            typer.echo("")
            typer.echo("  快速修复:")
            typer.echo("    · 安装外部工具: assetmap install-tools")
            typer.echo("    · 配置 API 密钥: assetmap configure")
            raise typer.Exit(1)

    @app.command("ai-check")
    def ai_check_command(
        config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
    ):
        config = load_config(config_path)
        if not config.ai.enabled:
            typer.echo("[ai] disabled in config.yaml", err=True)
            raise typer.Exit(1)
        messages = [
            {
                "role": "user",
                "content": "请简短回答：当前模型调用是否成功？",
            }
        ]
        try:
            response = chat_completion(
                config.ai,
                messages,
                temperature=0.2,
                max_completion_tokens=512,
            )
        except httpx.HTTPStatusError as exc:
            typer.echo(f"[ai] failed: HTTP {exc.response.status_code}", err=True)
            try:
                error = exc.response.json().get("error", {})
            except ValueError:
                error = {"message": exc.response.text[:500]}
            message = error.get("message") or error
            param = error.get("param")
            typer.echo(f"[ai] error: {message}", err=True)
            if param:
                typer.echo(f"[ai] param: {param}", err=True)
            raise typer.Exit(1)
        content = response.get("choices", [{}])[0].get("message", {}).get("content") or ""
        typer.echo("[ai] chat completion ok")
        if content:
            typer.echo(content[:1000])
