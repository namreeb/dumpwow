#!/usr/bin/python

import idc
import idaapi
import idautils
import ida_bytes
import ida_funcs
import traceback

# Get the name of the segment containing the given EA
def get_segment_name(ea):
    for seg_ea in idautils.Segments():
        if ea < seg_ea:
            continue
        seg_end = idc.get_segm_end(seg_ea)
        if ea > seg_end:
            continue
        return idc.get_segm_name(seg_ea)

def find_func_containing(ea):
    for segment_ea in idautils.Segments():
        if segment_ea > ea:
            continue
        segment_end = idc.get_segm_end(segment_ea)
        if segment_end < ea:
            continue
            
        for func_ea in idautils.Functions(segment_ea, segment_end):
            if func_ea > ea:
                continue
            func_end = idc.find_func_end(func_ea)
            if func_end <= ea:
                continue
            return func_ea
    return None

def find_game_init():
    strings = idautils.Strings()
    
    taint_ea = None
    
    # Find the string which is referenced only in CGameUI::Initialize
    for i in strings:
        if taint_ea is None and str(i) == 'Whether taint logging is enabled':
            taint_ea = i.ea
            break
            
    if taint_ea is None:
        raise RuntimeError('Unable to find CGGameUI::Initialize (1)')
        
    refs = list(idautils.DataRefsTo(taint_ea))
    
    if len(refs) != 1:
        raise RuntimeError('Unable to find CGGameUI::Initialize (2)')
    
    func_start = find_func_containing(refs[0])
    func_name = idc.get_func_name(func_start)
    
    mangled_name = '__ZN8CGGameUI10InitializeEv'
    
    if func_name != mangled_name:
        idc.set_name(func_start, mangled_name, SN_CHECK)

    print('CGGameUI::Initialize:  0x%x ' % func_start)
        
    return func_start

def find_framescript_register(game_init):
    game_init_end = idc.find_func_end(game_init)
    magic_string_found = False
    for head in idautils.Heads(game_init, game_init_end):
        disasm = idc.generate_disasm_line(head, 2)
        if not magic_string_found and '"FrameXML_Debug"' in disasm:
            magic_string_found = True
            continue
            
        if magic_string_found and disasm.startswith('call '):
            result = int(idc.get_operand_value(head, 0))
            func_name = idc.get_func_name(result)
            mangled_name = '__Z28FrameScript_RegisterFunctionPKcPFiP9lua_StateE'
            
            if func_name != mangled_name:
                idc.set_name(result, mangled_name, SN_CHECK)

            print('FrameScript::Register: 0x%08x' % result)
            return result
            
    raise RuntimeError('Unable to find FrameScript::Register (%d)' % \
        2 if magic_string_found else 1)

# Find all calls to FrameScript::Register
def find_register_calls(framescript_register):
    refs = list(idautils.CodeRefsTo(framescript_register, 1))
    print('Found %d calls to FrameScript::Register' % len(refs))
    return refs

# Examine the instructions in the given EA range for a Lua function array
def find_lua_function_array(start, end):
    for head in idautils.Heads(start, end):
        disasm = idc.generate_disasm_line(head, 2)
        if disasm.startswith('lea '):
            result = idc.get_operand_value(head, 1)
            return result
    raise RuntimeError('Unable to find Lua function array near 0x%08x' % start)

# Determine if the given EA is a valid entry in a Lua function array
def is_valid_lua_function_array_entry(ea):
    str_ea = ida_bytes.get_64bit(ea)
    func_name = ida_bytes.get_strlit_contents(str_ea, -1, 0)
    if func_name is None or len(func_name) == 0:
        return False
    func_ea = ida_bytes.get_64bit(ea+8)
    # If this points to somewhere other than the .text segment, it cant be valid
    if get_segment_name(func_ea) != '.text':
        return False

    f2 = find_func_containing(func_ea)
    # If no function is found, create one
    if f2 is None:
        ida_funcs.add_func(func_ea)
        print('Created function for Script_%s at 0x%08x' % (func_name, func_ea))
        f2 = func_ea
    elif f2 != func_ea:
        return False
    return find_func_containing(func_ea) == func_ea

# Determine if the given EA really points to a Lua function array
def is_valid_lua_function_array(ea):
    # First, verify that this EA is in the .data segment
    if get_segment_name(ea) != '.data':
        return False

    # Second, verify that the first two values point to a string and a function, respectively
    return is_valid_lua_function_array_entry(ea)

def main():
    print('\n\n')
    game_init = find_game_init()
    framescript_register = find_framescript_register(game_init)
    register_calls = find_register_calls(framescript_register)
    
    for c in register_calls:
        func_array = find_lua_function_array(c-0x20, c)
        if not is_valid_lua_function_array(func_array):
            print('WARNING: Invalid function array at 0x%08x (xref: 0x%08x)' % (func_array, c))
            continue            
            
        curr_ea = func_array
        while is_valid_lua_function_array_entry(curr_ea):
            str_ea = ida_bytes.get_64bit(curr_ea)
            func_ea = ida_bytes.get_64bit(curr_ea+8)
            func_name = ida_bytes.get_strlit_contents(str_ea, -1, 0)
            new_name = 'Script_' + func_name
            if idc.get_func_name(func_ea) != new_name:
                idc.set_name(func_ea, new_name)
            print('%s -> 0x%08x' % (new_name, func_ea))
            curr_ea += 16

if __name__ == '__main__':
    try:
        main()
    except:
        traceback.print_exc()