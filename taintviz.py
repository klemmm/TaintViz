#!/usr/bin/env python3
import eel
import json
import sys
import re
import os
import lief # Import LIEF
from triton import TritonContext, OPCODE, ARCH, Instruction, MODE, MemoryAccess, CPUSIZE, CALLBACK, REG, EXCEPTION, CALLBACK, OPERAND
from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from miasm.core.locationdb import LocationDB, ExprLoc
from miasm.ir.ir import IRBlock

import traceback
tainted_addresses = set()

def create_new_context():
    ctx = TritonContext()
    load_binary_lief(ctx, binary)
    ctx.setMode(MODE.ONLY_ON_TAINTED, True);
    ctx.setConcreteRegisterValue(ctx.registers.rbp, 0x7ffe602bfff8)
    ctx.setConcreteRegisterValue(ctx.registers.rsp, 0x7ffe602bfff8)

    return ctx

def load_binary_lief(ctx, path):
    try:
        binary = lief.parse(path)
    except lief.bad_file as e:
        print(f"[-] Error parsing binary with LIEF: {e}")
        sys.exit(1)

    if not binary:
        print(f"[-] Error parsing binary: {path}")
        sys.exit(1)

    if binary.header.machine_type == lief.ELF.ARCH.X86_64:
        ctx.setArchitecture(ARCH.X86_64)
    elif binary.header.machine_type == lief.ELF.ARCH.I386:
        ctx.setArchitecture(ARCH.X86)
    else:
        print(f"[!] Warning: Unsupported arch: {binary.header.machine_type}")
        sys.exit(1)

    print(f"[+] Loading binary '{path}' for arch {ctx.getArchitecture()}")
    for seg in binary.segments:
        if seg.type == lief.ELF.Segment.TYPE.LOAD:
            size = seg.virtual_size
            vaddr = seg.virtual_address
            print(f"[+] Loading segment type {seg.type} at {hex(vaddr)} size {hex(size)}")
            ctx.setConcreteMemoryAreaValue(vaddr, seg.content.tolist())

addr2cfg = {}
def get_cfg(address):
    if address in addr2cfg:
        return addr2cfg[address]
    cfg = disasm_engine.dis_multiblock(address)
    addr2cfg[address] = cfg
    return cfg

def build_graph_data(entry_point_address, tainted_addresses=set()):
    global called_from
    cfg = get_cfg(entry_point_address)
    graph_data = {
        'nodes': [],
        'edges': []
    }

    loc_str2key = {}
    for loc_key in loc_db.loc_keys:    
        loc_str2key[str(loc_key)] = loc_key
    for bb in cfg.blocks:
        block_is_traced = False
        bb_disasm = ""
        callee = None
        for inst in bb.lines:
            last_addr = inst.offset
            if inst.offset in traced:
                block_is_traced = True
            if inst.is_subcall():            
                callee = loc_db.get_location_offset(inst.args[0].loc_key)

            loc_str = f"{inst.offset:#0{12}x}"
            loc = loc_db.get_offset_location(inst.offset)
            if loc:
                names = loc_db.get_location_names(loc)
                if len(names) == 1:
                    loc_str, = names
                    if len(loc_str) > 12:
                        loc_str = loc_str[:12]
                    elif len(loc_str) < 12:
                        loc_str = "·"*(12 - len(loc_str)) + loc_str
            inst_str = inst.to_string()
            def name_or_addr(loc):
                names = loc_db.get_location_names(loc)
                if len(names) == 1:
                    name, = names
                    return name
                else:
                    return hex(loc_db.get_location_offset(loc))

            inst_str = re.sub(r'loc_key_([0-9a-fA-F]+)', lambda m: name_or_addr(loc_str2key[m.group()]), inst_str)
            disasm_line = f"{loc_str}: " + inst_str
            tainted_line = False
            
            if inst.offset in tainted_addresses:
                disasm_line = '<b>' + disasm_line + '</b>'
            bb_disasm += disasm_line + "\n"
        if block_is_traced:
            color = '#B0C0FF'
        else:
            color = '#F0F0F0'
        graph_data['nodes'].append({'id' : str(bb.loc_key), 'label': bb_disasm, 'callee': callee, 'color': color, 'last_addr': last_addr, 'address': loc_db.get_location_offset(bb.loc_key)})
    for edge in cfg.edges():
        source = cfg.loc_key_to_block(edge[0])
        taken = edge[1] != source.get_next()
        if taken:
            color = 'red'
        else:
            color = 'black'
        
        graph_data['edges'].append({'id': (str(edge[0]) + "->" + str(edge[1])), 'taken': taken, 'from': str(edge[0]), 'to': str(edge[1]), 'color': color})
    
    #print(f"Tainted addresses: {tainted_addresses}")

    return graph_data

def build_call_graph(entry_point_address, called_from={}, caller=None, seen=set()):
    global block_addresses
    if entry_point_address in seen:
        return
    seen.add(entry_point_address)
    cfg = get_cfg(entry_point_address)
    for bb in cfg.blocks:
        block_addresses.add(loc_db.get_location_offset(bb.loc_key))
        for inst in bb.lines:
            if caller is not None:
                called_from[inst.offset] = caller
                #print(f"Called from {hex(inst.offset)} to {hex(called_from[inst.offset])}")
            if inst.is_subcall():
                if isinstance(inst.args[0], ExprLoc):
                    callee_addr = loc_db.get_location_offset(inst.args[0].loc_key)
                    build_call_graph(callee_addr, called_from, inst.offset, seen)  
    return  


if len(sys.argv) != 2 and len(sys.argv) != 3:
    print(f'usage: {sys.argv[0]} <binary> [<function>]')
    sys.exit(1)

binary = sys.argv[1]
if len(sys.argv) == 2:
    function = "main"
else:
    function = sys.argv[2]

ctx = create_new_context()
loc_db = LocationDB()
container = Container.from_stream(open(binary, "rb"), loc_db)

call_stack = []
machine_name = container.arch
machine = Machine(machine_name)
print(f"[INFO] Loaded  {machine_name} binary.")

disasm_engine = machine.dis_engine(container.bin_stream, loc_db=loc_db)

entry_point_address = loc_db.get_name_offset(function)
if entry_point_address is None:
    print(f"[ERR] Failed to find function {function} in binary {binary}")
    sys.exit(1)

called_from = {}
traced = set()
block_addresses = set()
build_call_graph(entry_point_address, called_from)

graph_data = build_graph_data(entry_point_address)


eel.init('web')

taint_rules = []
next_rule_id = 0
rule_address_lookup = set()

@eel.expose
def get_graph_data():
    """Returns the graph data to the frontend."""
    print("Frontend requested graph data.")
    return graph_data



@eel.expose
def add_taint_rule(rule_data):
    """Adds a new taint rule received from the frontend."""
    global next_rule_id
    global ctx
    try:
        address = rule_data.get('address', '').strip()
        taint_type = rule_data.get('type', 'register')
        target = rule_data.get('target', '').strip()
        offset = rule_data.get('offset', '0').strip() or '0'
        size = rule_data.get('size', '').strip()
        sizeMultiplier = rule_data.get('sizeMultiplier', '').strip()   

        if not address or not target:
            return "Error: Address and Target are required."

        if taint_type in ['memory', 'relative_memory'] and not size:
            return "Error: Size is required for memory taints."

        # Try to resolve symbol name to address
        try:

            resolved_address = loc_db.get_name_offset(address)
            if resolved_address is None:
                resolved_address = int(address, 0)

        except ValueError:
            return f"Error: Invalid address '{address}'. Use hex (0x...) or symbol name."

        try:
            new_rule = {
                'id': next_rule_id,
                'address': resolved_address,
                'address_str': address,
                'type': taint_type,
                'target': int(target, 0) if taint_type in ['memory'] else getattr(ctx.registers, target),                
                'target_str': target,
                'offset': int(offset, 0),
                'size': (getattr(ctx.registers, size, None) if hasattr(ctx.registers, size) else int(size, 0)) if size else None,
                'size_str': size,
                'sizeMultiplier': int(sizeMultiplier, 0) if sizeMultiplier else None
            }
        except AttributeError as e:
            if "has no attribute" in str(e):
                return f"Error: Invalid register name '{target}'"
            raise e
        except ValueError as e:
            return f"Error: Invalid numeric value in rule: {str(e)}"

        taint_rules.append(new_rule)
        next_rule_id += 1
        rule_address_lookup.add(new_rule['address'])
        print(f"Added Taint Rule: {new_rule}")
        return taint_rules
    except Exception as e:
        return f"Error: {str(e)}"
        

@eel.expose
def delete_taint_rule(rule_id):
    """Deletes a taint rule by its unique ID."""
    global taint_rules
    initial_length = len(taint_rules)
    for removed_rule in [rule for rule in taint_rules if rule['id'] == rule_id]:
        rule_address_lookup.discard(removed_rule['address'])
    taint_rules = [rule for rule in taint_rules if rule['id'] != rule_id]

    if len(taint_rules) < initial_length:
        print(f"Deleted Taint Rule with ID: {rule_id}")
    else:
        print(f"Warning: Taint Rule with ID {rule_id} not found for deletion.")
    return taint_rules


def dispatch_syscall(ctx, syscall_no):
    print(f"Syscall number: {syscall_no}")
    # import syscall.py module
    try:
        # Reload the syscall module if it's already loaded
        if 'syscall' in sys.modules:
            import importlib
            importlib.reload(sys.modules['syscall'])
        import syscall
        syscall.dispatch_syscall(ctx,syscall_no)

    except ImportError:
        print("No syscall module found")
    except Exception as e:
        print(f"Error dispatching syscall: {e}")
        traceback.print_exc()

paths_constraints = None

@eel.expose
def start_analysis():
    """Starts the analysis of the graph."""
    global graph_data
    global tainted_addresses
    global traced
    global paths_constraints
    global ctx
    print("Starting analysis...")  
    paths_constraints = None
    instruction_count = 0
    MAX_INSTRUCTIONS = 100000
    current_pc = entry_point_address
    tainted_addresses = set()
    
    #reset context
    ctx = create_new_context()


    while current_pc != 0 and instruction_count < MAX_INSTRUCTIONS:
        traced.add(current_pc)

        opcode = ctx.getConcreteMemoryAreaValue(current_pc, 16)

        if opcode.startswith(b"\x0f\x05"):
            syscall_no = ctx.getConcreteRegisterValue(ctx.registers.rax)
            dispatch_syscall(ctx, syscall_no)
            ctx.setConcreteRegisterValue(ctx.registers.rip, current_pc + 2)
        else:
            inst = Instruction()
            inst.setOpcode(opcode)
            inst.setAddress(current_pc)            
            status = ctx.processing(inst)
            if status != 0:
                print(f"Error processing instruction at {hex(current_pc)}: {status}")
                break

        instruction_count += 1
        #print(inst)
        if current_pc in rule_address_lookup:
            print(f"Taint rule triggered at {hex(current_pc)}")
            rule = next((rule for rule in taint_rules if rule['address'] == current_pc))            
            print(f"Taint rule: {rule}")
            if rule['type'] == 'memory':
                start_addr = rule['target']
                size = rule['size']
                if type(size) is not int:
                    size = ctx.getConcreteRegisterValue(size)

                for i in range(size*rule['sizeMultiplier']):
                    ctx.setTaintMemory(MemoryAccess(start_addr + i, 1), True)
                    ctx.symbolizeMemory(MemoryAccess(start_addr + i, 1), "mem_" + hex(start_addr + i))

            elif rule['type'] == 'relative_memory':
                start_addr = ctx.getConcreteRegisterValue(rule['target'])
                offset = rule['offset']
                if type(start_addr) is not int:
                    start_addr = ctx.getConcreteRegisterValue(start_addr)
                size = rule['size']
                if type(size) is not int:
                    size = ctx.getConcreteRegisterValue(size)
                for i in range(size*rule['sizeMultiplier']):
                    ctx.setTaintMemory(MemoryAccess(start_addr + offset + i, 1), True)
                    ctx.symbolizeMemory(MemoryAccess(start_addr + offset + i, 1), "mem_" + hex(start_addr + offset + i))
                    print(f"Tainted memory at {hex(start_addr + offset + i)}")

            elif rule['type'] == 'register':
                ctx.setTaintRegister(rule['target'], True)
                ctx.symbolizeRegister(rule['target'], "reg_" + rule['target_str'])
        
        # Add instruction's address to tainted_addresses if it reads from tainted values
        #print(f"Instruction: {inst}")        
        for mem, _ in inst.getLoadAccess():
            print("Read memory: ", mem)
            if ctx.isMemoryTainted(mem):
                tainted_addresses.add(current_pc)
                break
        for reg, _ in inst.getReadRegisters():
            print("Read register: ", reg)
            if ctx.isRegisterTainted(reg):
                tainted_addresses.add(current_pc)
                break
        

        current_pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
    print(f"Analysis completed after {instruction_count} instructions.")

    changed = True
    while changed:
        changed = False
        to_add = set()
        for address in tainted_addresses:
            # If a function contains tainted instructions, also taint the caller
            current_address = address
            while current_address in called_from:
                if called_from[current_address] not in tainted_addresses:
                    to_add.add(called_from[current_address])
                    changed = True
                current_address = called_from[current_address]
        tainted_addresses.update(to_add)
    graph_data = build_graph_data(entry_point_address, tainted_addresses)
    paths_constraints = ctx.getPathConstraints()
    return graph_data

@eel.expose
def enter_cfg(node_id):
    global graph_data
    global call_stack
    global entry_point_address

    node = next((node for node in graph_data['nodes'] if node['id'] == node_id), None)

    if node is not None and node['callee'] is not None:
        print(f"Entering CFG at node {node_id} with callee {node['callee']}")
        call_stack.append(entry_point_address)
        entry_point_address = node['callee']
        graph_data = build_graph_data(entry_point_address, tainted_addresses)        
        return graph_data
    else:
        return None

@eel.expose
def exit_cfg():
    global call_stack
    global entry_point_address
    global graph_data
    if len(call_stack) > 0:
        entry_point_address = call_stack.pop()
        print(f"Exiting CFG to {entry_point_address}")
        graph_data = build_graph_data(entry_point_address, tainted_addresses)
        return graph_data
    else:
        return None

@eel.expose
def print_path_condition(edge_id):
    global paths_constraints
    if paths_constraints is None:
        return("No path constraints yet")
        
    edge = next((edge for edge in graph_data['edges'] if edge['id'] == edge_id), None)
    if edge is not None:
        print(f"Getting path condition for edge {edge_id}, is taken: {edge['taken']}")
        sink = next((node for node in graph_data['nodes'] if node['id'] == edge['to']), None)
        source = next((node for node in graph_data['nodes'] if node['id'] == edge['from']), None)
        if source is None or sink is None:
            print("Source or sink not found")
            return
        



        source_address = source['last_addr']
        sink_address = sink['address']

        for constraint in paths_constraints:
            for branchConstraint in constraint.getBranchConstraints():
                if branchConstraint['srcAddr'] == source_address and branchConstraint['dstAddr'] == sink_address:
                    #ast = ctx.simplify(branchConstraint['constraint'], solver=True)
                    model = ctx.getModel(branchConstraint['constraint'])
                    if model:
                        return str(model)
                    else:
                        return "UNSAT"
        return "No path condition found for this edge"
    else:
        print(f"Edge with ID {edge_id} not found.")

print("Starting Eel application...")
try:
    eel.start('main.html', block=True)
except (SystemExit, MemoryError, KeyboardInterrupt):
    print("Application closed.")
