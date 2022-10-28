#!/usr/bin/python
# IDApython script using IDA Processor Extension Plugin to defeat control flow obfuscation in Guloader
#Place this script in the "$IDAUSR/plugins" directory
#Author: Mark Lim malim@paloaltonetworks.com
# -*- coding: utf-8 -*-
import idaapi
import idc
import ida_nalt
import ida_idp
import ida_bytes
import ida_ua
import os
              
class guloader_veh_hook(idaapi.IDP_Hooks):

    def __init__(self):
        idaapi.IDP_Hooks.__init__(self)

    def ev_ana_insn(self, insn):
            
        b = bytes(idaapi.get_bytes(insn.ea, 2))     #read 2 bytes
        f = idaapi.get_flags(insn.ea)               #read flags of current instruction
        if idaapi.is_tail(f):                       #check if current byte is inside existing instruction/data to prevent false positive
            return False

        if b[0] ==0xCC:                             #look for CC byte that trigger VEH
            offset = b[1] ^ 0xA9                    #decode offset value
            idaapi.put_byte(insn.ea, 0xEB)          #patch CC byte with JMP instruction
            idaapi.put_byte(insn.ea+1, offset-2)    #patch encoded offset with decoded offset
            print("Patched bytes at: 0x%X" % insn.ea)
            return True

        return True


class guloader_veh(idaapi.plugin_t):

    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = 'Fix CC bytes for Guloader'
    help = 'Fix CC bytes for Guloader on the fly'
    wanted_name = 'Fix CC bytes for Guloader'
    wanted_hotkey = "Control + Alt + p"
    hook = None

    def init(self):
        self.hook = None
        if not "Guloader" in ida_nalt.get_root_filename() or idaapi.ph_get_id() != idaapi.PLFM_386: #Enable this plug-in to only work for specific file
            return idaapi.PLUGIN_SKIP
        print("Guloader found!")

        self.hook = guloader_veh_hook()
        self.hook.hook()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if self.hook:
            self.hook.unhook()


def PLUGIN_ENTRY():
    return guloader_veh()

