import immlib
import struct

def main(args):

	if (len(args) != 1):
		return "Must be only one parameter"
	
	dbg = immlib.Debugger()
	moduleobj = dbg.getModule(args[0])
	
	if (moduleobj == None):
		return "Could not find module %s" % (args[0])
	
	modisaslr = True
	modisnx = True
	modiscfg = True
	
	mod       = moduleobj
	mzbase    = mod.getBaseAddress()			
	
	if mzbase > 0:
		
		peoffset=struct.unpack('<L',dbg.readMemory(mzbase+0x3c,4))[0]
		pebase=mzbase+peoffset
						
		flags = struct.unpack('<H',dbg.readMemory(pebase+ 0x5e,2))[0]
		
				
		#aslr
		if (flags&0x0040)==0:  	# 'IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE
			modisaslr=False
		#nx
		if (flags&0x0100)==0:
			modisnx=False
		#cfg
		if (flags&0x4000)==0:	#IMAGE_DLLCHARACTERISTICS_GUARD_CF
			modiscfg=False
	
	else:
		return "Error: mzbase <= 0"
		
	s = "%s: ASLR=%s DEP=%s CFG=%s" % (args[0], modisaslr, modisnx, modiscfg)
	return s