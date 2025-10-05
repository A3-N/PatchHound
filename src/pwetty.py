# src/pwetty.py

ASCII_ART = r"""
                                  .-.
     (___________________________()6 `-,
     (   ______________________   /''"`
     //\\                      //\\
     "" ""                     "" ""
               PatchHound  -  by A3-N
 ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
""".strip("\n")

GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"

def paint(text: str, color: str, nocolor: bool = False) -> str:
    return f"{color}{text}{RESET}" if not nocolor else text

def markers(nocolor: bool = False) -> dict:
    """Return pre-colored log markers."""
    return {
        "ok": paint("[+]", GREEN, nocolor),
        "warn": paint("[!]", YELLOW, nocolor),
        "info": paint("[*]", CYAN, nocolor),
    }

def progress_bar(done: int, total: int, nocolor: bool, width: int = 28):
    total = max(total, 1)
    ratio = min(max(done / total, 0), 1)
    fill  = int(width * ratio)

    block_filled = "█"
    block_empty  = "░"

    green = "" if nocolor else "\x1b[32m"
    dim   = "" if nocolor else "\x1b[2m"
    reset = "" if nocolor else "\x1b[0m"

    filled = block_filled * fill
    empty  = block_empty  * (width - fill)

    bar = f"{green}{filled}{reset}{dim}{empty}{reset}"
    pct = int(ratio * 100)
    return bar, pct
