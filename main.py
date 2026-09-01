#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Punto de entrada centralizado — Generador de Informes CREM / TrendAI

Menú único para elegir cómo trabajar:
  1) Terminal   → informe_crem.py   (flujo interactivo en consola)
  2) Dashboard  → crem_dashboard.py (ventana de escritorio, Flask + PyQt6)

Uso:
    python main.py                → menú interactivo
    python main.py --terminal     → lanza directamente la versión de terminal
    python main.py --dashboard    → lanza directamente el dashboard
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path

if sys.platform == "win32":
    os.system("mode con cols=100 lines=34")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

_theme = Theme({
    "info": "cyan", "warning": "bold yellow", "error": "bold red",
    "success": "bold green", "dim": "dim white", "accent": "bold cyan",
})
console = Console(theme=_theme, highlight=False)

RAIZ           = Path(__file__).resolve().parent
SCRIPT_INFORME = RAIZ / "informe_crem.py"
SCRIPT_DASH    = RAIZ / "crem_dashboard.py"

VERSION  = "2.0"
PROYECTO = "Generador de Informes CREM — TrendAI"


def ok(msg):   console.print(f"  [success]✓[/] {msg}")
def err(msg):  console.print(f"  [error]✗[/] {msg}")
def warn(msg): console.print(f"  [warning]![/] {msg}")
def info(msg): console.print(f"  [info]•[/] {msg}")


def banner():
    console.clear()
    console.print()
    titulo = Text.assemble(
        (" TREND ", "bold white on cyan"),
        (" AI ", "bold cyan on grey15"),
        ("   Generador de Informes CREM", "bold cyan"),
    )
    sub = Text(f"v{VERSION} · punto de entrada centralizado", style="dim")
    console.print(Panel(
        Align.center(Text.assemble(titulo, "\n", sub)),
        border_style="cyan", padding=(1, 4), expand=False))
    console.print()


def _tarjeta(num, icono, titulo, desc, color):
    """Devuelve un panel-tarjeta para una opción del menú."""
    cuerpo = Text.assemble(
        (f"{icono}  ", ""),
        (titulo, f"bold {color}"),
        ("\n", ""),
        (desc, "dim"),
    )
    return Panel(cuerpo, title=f"[bold {color}]{num}[/]",
                 border_style=color, padding=(1, 2), width=44)


def menu_principal() -> str | None:
    """Muestra el menú y devuelve la opción elegida ('dashboard' | 'terminal' | None)."""
    banner()
    tabla = Table.grid(padding=(0, 2))
    tabla.add_column()
    tabla.add_column()
    tabla.add_row(
        _tarjeta("1", "📊", "Dashboard (Principal)", "crem_dashboard.py\nInterfaz gráfica recomendada Command Center.", "cyan"),
        _tarjeta("2", "🖥️ ", "Versión Terminal", "informe_crem.py\nFlujo interactivo paso a paso en consola.", "magenta"),
    )
    console.print(tabla)
    console.print("\n  [dim]0  ·  Salir[/]\n")

    while True:
        console.print("  [accent]¿Qué versión quieres abrir?[/]  [dim](1 · 2 · 0 — Enter = 1)[/]")
        val = input("  → ").strip().lower()
        if not val or val in ("1", "dashboard", "d"): return "dashboard"
        if val in ("2", "terminal", "t"):             return "terminal"
        if val in ("0", "q", "salir", "exit"):
            return None
        warn("Opción no válida. Escribe 1, 2 o 0.")


def ejecutar(cmd: list[str], titulo: str) -> int:
    """Lanza un script como subprocess heredando stdin/stdout/stderr."""
    console.print()
    console.print(Panel(f"[dim]{titulo}[/]", border_style="dim", expand=False))
    console.print()
    try:
        return subprocess.run(cmd, cwd=str(RAIZ)).returncode
    except KeyboardInterrupt:
        warn("Interrumpido por el usuario.")
        return 130


def lanzar_terminal() -> int:
    if not SCRIPT_INFORME.exists():
        err(f"No se encontró {SCRIPT_INFORME}"); return 1
    info("Abriendo versión de terminal (informe_crem)…")
    return ejecutar([sys.executable, str(SCRIPT_INFORME)], "informe_crem.py")


def lanzar_dashboard() -> int:
    if not SCRIPT_DASH.exists():
        err(f"No se encontró {SCRIPT_DASH}"); return 1
    info("Abriendo dashboard (crem_dashboard)…")
    return ejecutar([sys.executable, str(SCRIPT_DASH)], "crem_dashboard.py")


def main():
    parser = argparse.ArgumentParser(description=PROYECTO)
    grupo = parser.add_mutually_exclusive_group()
    grupo.add_argument("--terminal",  action="store_true", help="Lanza directamente la versión de terminal")
    grupo.add_argument("--dashboard", action="store_true", help="Lanza directamente el dashboard")
    args = parser.parse_args()

    if args.terminal:
        return lanzar_terminal()
    if args.dashboard:
        return lanzar_dashboard()

    opt = menu_principal()
    if opt == "terminal":
        return lanzar_terminal()
    if opt == "dashboard":
        return lanzar_dashboard()

    console.print("\n  [dim]Hasta luego.[/]\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except KeyboardInterrupt:
        console.print("\n\n  [dim]Interrumpido.[/]\n")
        sys.exit(130)
