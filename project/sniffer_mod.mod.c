#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
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
	{ 0x885b74e3, "module_layout" },
	{ 0xf4e7c8c5, "cdev_del" },
	{ 0x500e2b1d, "kmalloc_caches" },
	{ 0x992ad80e, "cdev_init" },
	{ 0x4c4fef19, "kernel_stack" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0xed80703e, "single_open" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0x703ba0c6, "single_release" },
	{ 0x2762655b, "skb_copy" },
	{ 0xf22449ae, "down_interruptible" },
	{ 0x21a7d814, "seq_printf" },
	{ 0xe12fb4d1, "nf_register_hook" },
	{ 0x7485e15e, "unregister_chrdev_region" },
	{ 0x3de8d6ef, "seq_read" },
	{ 0x6395be94, "__init_waitqueue_head" },
	{ 0x4f8b5ddb, "_copy_to_user" },
	{ 0x3d431bf9, "current_task" },
	{ 0x27e1a049, "printk" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0xb4390f9a, "mcount" },
	{ 0x27cdc719, "cdev_add" },
	{ 0x1000e51, "schedule" },
	{ 0xcde3e782, "kmem_cache_alloc_trace" },
	{ 0xcf21d241, "__wake_up" },
	{ 0xe5c8c93f, "proc_create_data" },
	{ 0x24df6f8e, "nf_unregister_hook" },
	{ 0x8fe3278, "seq_lseek" },
	{ 0x5c8b5ce8, "prepare_to_wait" },
	{ 0x71e3cecb, "up" },
	{ 0xfa66f77c, "finish_wait" },
	{ 0x29537c9e, "alloc_chrdev_region" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "40AEFE0B5A70F6FD484875B");
