from vmmpy import *
from io import BytesIO

args = (["-device", "fpga", "-memmap", "auto"])
process = 'snes9x-x64.exe'

VmmPy_Initialize(args)
pid = VmmPy_PidGetFromName(process)

process_info = VmmPy_ProcessGetInformation(pid)
print(str(process_info) + "\n")

memory_map = VmmPy_ProcessGetPteMap(pid=pid, is_identify_modules=True)
for m in memory_map:
    if process == m['tag'] and m['flags'] == '-rw-':
        print(str(m) + "\n")
        va_physical_memory = VmmPy_MemVirt2Phys(pid, m['va'])
        result = VmmPy_MemReadScatter(-1, [va_physical_memory])
        data = VmmPy_UtilFillHexAscii(result[0]['data'])
        print(str(data))

#module = VmmPy_ProcessGetModuleFromName(pid, "snes9x-x64.exe")
#print(str(module) + "\n")

#physical_memory = VmmPy_MemVirt2Phys(pid, module['va'])
#print(str(physical_memory) + "\n")

#memory = VmmPy_UtilFillHexAscii(VmmPy_MemRead(pid=pid, address=module['va'], length=0x100, flags=VMMPY_FLAG_NOCACHE))
#print(str(memory) + "\n")

#result = VmmPy_MemReadScatter(-1, [physical_memory])
#print(result[0]['data'])
