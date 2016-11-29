
def get_permission_backer(proj):
	permission_map = { }
	for obj in proj.loader.all_objects:
		for seg in obj.segments:
			perms = 0
			# bit values based off of protection bit values from sys/mman.h
			if seg.is_readable:
				perms |= 1 # PROT_READ
			if seg.is_writable:
				perms |= 2 # PROT_WRITE
			if seg.is_executable:
				perms |= 4 # PROT_EXEC
			permission_map[(obj.rebase_addr + seg.min_addr, obj.rebase_addr + seg.max_addr)] = perms
	
	return (proj.loader.main_bin.execstack, permission_map)