#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x4f6967fe, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0xa45c06f5, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x739ea820, __VMLINUX_SYMBOL_STR(maxSize) },
	{ 0x1836555b, __VMLINUX_SYMBOL_STR(msgsendB_begin_addr) },
	{ 0xeb0a9196, __VMLINUX_SYMBOL_STR(msgrcvA_begin_addr) },
	{ 0x4b9ca6c7, __VMLINUX_SYMBOL_STR(kthread_create_on_node) },
	{ 0x20d9327c, __VMLINUX_SYMBOL_STR(AB_shmAddr) },
	{ 0xcaf4c87c, __VMLINUX_SYMBOL_STR(my_msgrcvA) },
	{ 0xc08493d4, __VMLINUX_SYMBOL_STR(fs_start) },
	{ 0x7532588a, __VMLINUX_SYMBOL_STR(alloc_pages_exact) },
	{ 0x81a79b5c, __VMLINUX_SYMBOL_STR(init_shm) },
	{ 0x10989194, __VMLINUX_SYMBOL_STR(my_msgsendA) },
	{ 0xa23d7854, __VMLINUX_SYMBOL_STR(current_task) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x77caed86, __VMLINUX_SYMBOL_STR(kthread_stop) },
	{ 0x1e6d26a8, __VMLINUX_SYMBOL_STR(strstr) },
	{ 0xe12ce6d0, __VMLINUX_SYMBOL_STR(my_msgsendB) },
	{ 0x71c161a5, __VMLINUX_SYMBOL_STR(init_waitqueue) },
	{ 0x520cef7e, __VMLINUX_SYMBOL_STR(BA_shmAddr) },
	{ 0xa5fc3995, __VMLINUX_SYMBOL_STR(msgsendA_begin_addr) },
	{ 0x7afbe6af, __VMLINUX_SYMBOL_STR(fs_temp) },
	{ 0x35ec68b4, __VMLINUX_SYMBOL_STR(pv_cpu_ops) },
	{ 0x96121fd0, __VMLINUX_SYMBOL_STR(wake_up_process) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
	{ 0x57b85a3c, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xf5eb2fdb, __VMLINUX_SYMBOL_STR(msqid_from_fs_to_kernel) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x69acdf38, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0x56c0fd58, __VMLINUX_SYMBOL_STR(msgrcvB_begin_addr) },
	{ 0x3b40bf38, __VMLINUX_SYMBOL_STR(my_msgrcvB) },
	{ 0x39572607, __VMLINUX_SYMBOL_STR(msqid_from_kernel_to_fs) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "09C103CF5A6911724A59659");
