from colorama import Fore, Back, Style
from colorama import init as color_init

def output_good(line):
    print(Fore.GREEN + Style.BRIGHT + "[+]" + Style.RESET_ALL, line)

def output_indifferent(line):
    print(Fore.BLUE + Style.BRIGHT + "[*]" + Style.RESET_ALL, line)

def output_error(line):
    print(Fore.RED + Style.BRIGHT + "[-] !!! " + Style.NORMAL, line, Style.BRIGHT + "!!!")

def output_bad(line):
    print(Fore.RED + Style.BRIGHT + "[-]" + Style.RESET_ALL, line)

def output_info(line):
    print(Fore.WHITE + Style.BRIGHT + "[*]" + Style.RESET_ALL, line)
