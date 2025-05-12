#include <linux/mm.h>
#include <linux/module.h>
#include <linux/preempt.h>
#include "nv-linux.h"
#include "os-interface.h"

/* Miscellaneous internals */

#ifndef preempt_enable_no_resched
#ifdef CONFIG_PREEMPT_COUNT
#define sched_preempt_enable_no_resched() \
	do { \
		barrier(); \
		preempt_count_dec(); \
	} while (0)
#define preempt_enable_no_resched() sched_preempt_enable_no_resched()
#else
#define preempt_enable_no_resched() barrier()
#endif
#endif

#ifndef X86_CR4_CET_BIT
#define X86_CR4_CET_BIT 23
#endif

#ifndef STACK_FRAME_NON_STANDARD
#define STACK_FRAME_NON_STANDARD(f)
#endif

#ifndef VUP_MERGED_DRIVER
#define VUP_MERGED_DRIVER 0
#endif


/* TODO: Find some way to do this dynamically */

#if defined(NV_VGPU_KVM_BUILD)
#define RM_IOCTL_OFFSET	0xc98e90
#define BLOB_TEXT_SIZE	0xda7964
#elif defined(NV_GRID_BUILD)
#define RM_IOCTL_OFFSET 0xc98f50
#define BLOB_TEXT_SIZE	0xda7a24
#endif


/* Globals */

#if defined(NV_GRID_BUILD)
static int vup_gridext = 1;
module_param_named(gridext, vup_gridext, int, 0400);
#endif
static int vup_vgpukvm_opt;
static int vup_cr4_cet_enabled;


/* TODO: VUP hooks */

#if 0

struct vup_hook_info {
	void (*func)(void);
	const struct kernel_param *param;
	u32 offset;
	int ovgpu;
	s16 pbytes[14];
};

#define VUP_HOOK(offs, name, vgpuopt, cbytes...) \
	{ vup_hook_##name##_naked, &__param_##name, offs, vgpuopt, { cbytes, -1 } }

#if defined(NV_VGPU_KVM_BUILD)
static int vup_cudahost = VUP_MERGED_DRIVER;
module_param_named(cudahost, vup_cudahost, int, 0400);

__attribute__((used))
static void vup_hook_cudahost(u8 *flag)
{
	printk(KERN_INFO "nvidia: vup_hook cudahost=%d flag=%d\n",
	       vup_cudahost, *flag);
	if (vup_cudahost > 0)
		*flag = vup_cudahost;
}

__attribute__((naked, no_instrument_function, no_stack_protector,
               no_split_stack, noclone, function_return("keep")))
static void vup_hook_cudahost_naked(void)
{
	asm (
		"push   %rdi            \n"
		"push   %rsi            \n"
		"push   %rdx            \n"
		"push   %rcx            \n"
		"push   %r8             \n"
		"push   %r9             \n"
		"lea   0x50c(%rbx), %rdi\n"
		"call  vup_hook_cudahost\n"
		"pop    %r9             \n"
		"pop    %r8             \n"
		"pop    %rcx            \n"
		"pop    %rdx            \n"
		"pop    %rsi            \n"
		"pop    %rdi            \n"
		"cmpb   $0, 0x824(%r13) \n"
		"ret                    \n"
		"int3                   \n"
	);
}
STACK_FRAME_NON_STANDARD(vup_hook_cudahost_naked);
#endif

static int vup_vupdevid;
module_param_named(vupdevid, vup_vupdevid, int, 0400);

__attribute__((used))
static u32 vup_hook_vupdevid(u32 devid, u32 subdevid)
{
	printk(KERN_INFO "nvidia: vup_hook_vupdevid 10de:%04x %04x:%04x\n",
	       devid, subdevid & 0xffff, subdevid >> 16);
	return vup_vupdevid;
}

__attribute__((naked, no_instrument_function, no_stack_protector,
               no_split_stack, noclone, function_return("keep")))
static void vup_hook_vupdevid_naked(void)
{
	asm (
		"push   %rdi            \n"
		"push   %rsi            \n"
		"push   %rdx            \n"
		"push   %rcx            \n"
		"push   %r8             \n"
		"push   %r9             \n"
		"mov    %r15, %rdi      \n"
		"mov   0xaa8(%r14), %esi\n"
		"call  vup_hook_vupdevid\n"
		"test   %eax, %eax      \n"
		"mov    $1, %r13d       \n"
		"cmovne %eax, %r15d     \n"
		"pop    %r9             \n"
		"pop    %r8             \n"
		"pop    %rcx            \n"
		"pop    %rdx            \n"
		"pop    %rsi            \n"
		"pop    %rdi            \n"
		"mov    %r12, %rax      \n"
		"mov    %r15d, %ebx     \n"
		"ret                    \n"
		"int3                   \n"
	);
}
STACK_FRAME_NON_STANDARD(vup_hook_vupdevid_naked);

static int vup_klogtrace_filter[][2] = {
	{ 0xbfe247, 0x0684 },
	{ 0xe3cee1, 0x064C },
};

static int vup_klogtrace;
module_param_named(klogtrace, vup_klogtrace, int, 0600);

static int vup_klogtrace_filtercnt = 8;
module_param_named(klogtracefc, vup_klogtrace_filtercnt, int, 0600);

__attribute__((used))
static void vup_hook_klogtrace(u64 rdi, u64 rsi)
{
	int i;
	int id, pt, a1, a2;
	if (vup_klogtrace < 1)
		return;
	id = rdi & 0xffffff;
	pt = (rsi >> 16) & 0xffff;
	a1 = (rdi >> 24) & 0xff;
	a2 = rsi & 0xffff;
	if (vup_klogtrace == 1) {
		for (i = 0; i < ARRAY_SIZE(vup_klogtrace_filter); i++)
			if (id == vup_klogtrace_filter[i][0]
			    && pt == vup_klogtrace_filter[i][1])
			{
				if (vup_klogtrace_filtercnt == 0)
					return;
				vup_klogtrace_filtercnt--;
			}
	}
	printk(KERN_DEBUG "NVTRACE %06x:%04x %04x%02x\n", id, pt, a2, a1);
}

__attribute__((naked, no_instrument_function, no_stack_protector,
               no_split_stack, noclone, function_return("keep")))
static void vup_hook_klogtrace_naked(void)
{
	asm (
		"push   %rdi            \n"
		"push   %rsi            \n"
		"push   %rdx            \n"
		"push   %rcx            \n"
		"push   %r8             \n"
		"push   %r9             \n"
		"call vup_hook_klogtrace\n"
		"pop    %r9             \n"
		"pop    %r8             \n"
		"pop    %rcx            \n"
		"pop    %rdx            \n"
		"pop    %rsi            \n"
		"pop    %rdi            \n"
		"sub    $0x440, %rbp    \n"
		"ret                    \n"
		"int3                   \n"
	);
}
STACK_FRAME_NON_STANDARD(vup_hook_klogtrace_naked);

static struct vup_hook_info vup_hooks[] = {
#if defined(NV_VGPU_KVM_BUILD)
	VUP_HOOK(0x00416B9C, cudahost, 1, 0x41, 0x80, 0xBD, 0x24, 0x08, 0x00, 0x00, 0x00),
	VUP_HOOK(0x0051E3A7, vupdevid, 1, 0x4C, 0x89, 0xE0, 0x44, 0x89, 0xFB),
	VUP_HOOK(0x00016185, klogtrace,0, 0x48, 0x81, 0xED, 0x40, 0x04, 0x00, 0x00),
#else
	VUP_HOOK(0x0051E3A7, vupdevid, 1, 0x4C, 0x89, 0xE0, 0x44, 0x89, 0xFB),
	VUP_HOOK(0x00016185, klogtrace,0, 0x48, 0x81, 0xED, 0x40, 0x04, 0x00, 0x00),
#endif
};

static void vup_inject_hooks(u8 *blob)
{
	int i, j, arg, size;
	struct vup_hook_info *hi;
	char logbuf[128];

	logbuf[0] = '\0';
	for (i = 0; i < ARRAY_SIZE(vup_hooks); i++) {
		hi = &vup_hooks[i];
		if (vup_vgpukvm_opt == 0 && hi->ovgpu)
			continue;
		j = strlen(logbuf);
		size = sizeof(logbuf) - j;
		arg = *(int *)hi->param->arg;
		j = snprintf(logbuf + j, size, arg < 10 ? " %s=%d" : " %s=0x%x",
			     hi->param->name, arg);
		if (j >= size)
			printk(KERN_WARNING "nvidia: vup_inject_hooks "
			       "logbuf too small (%s)\n", hi->param->name);
		if (arg < 0)
			continue;
		for (j = 0; hi->pbytes[j] >= 0; j++)
			if (blob[hi->offset + j] != hi->pbytes[j])
				break;
		if (hi->pbytes[j] >= 0) {
			printk(KERN_ERR "nvidia: vup_inject_hooks %s "
			       "failed (%d)\n", hi->param->name, j);
			continue;
		}
		j -= 5;
		blob[hi->offset + j] = 0xe8;
		*(u32 *)(&blob[hi->offset + j + 1]) =
			(u8 *)hi->func - &blob[hi->offset + j + 5];
		for (j--; j >= 0; j--)
			blob[hi->offset + j] = 0x90;
	}
	printk(KERN_INFO "nvidia: vup_inject_hooks cetbit=%d%s\n",
	       vup_cr4_cet_enabled, logbuf);
}

#endif


/* VUP patches */

// FIXME: Simplify/Optimise the assembly. Find some way to ignore padding.

struct vup_patch_item {
	int *oldsig;
	int *newsig;
	size_t length;
};

struct vup_patch_info {
	const struct kernel_param *param;
	struct vup_patch_item *items;
	int count;
	int enabv;
	int ovgpu;
};

#define VUP_PATCH_DEF(name, defval, enabval, vgpuopt) \
static int vup_patch_##name = defval; \
module_param_named(vup_##name, vup_patch_##name, int, 0400); \
static struct vup_patch_info vup_patch_info_##name = { \
	.param = &__param_vup_##name, \
	.items = vup_diff_##name, \
	.count = ARRAY_SIZE(vup_diff_##name), \
	.enabv = enabval, \
	.ovgpu = vgpuopt, \
}
#define VUP_PATCH(name) &vup_patch_info_##name

#if defined(NV_VGPU_KVM_BUILD)

// Ignore a result of the `os_mem_cmp()` thunk in a function that also calls one with string references to licenses - "NVIDIA Virtual PC", etc.
static int vup_sigpatch_vgpusig_old[] = { 0x85, 0xC0, 0x0F, 0x85, -1, -1, -1, -1, 0x48, 0x8B, 0x7D, -1, 0xE8, -1, -1, -1, -1, 0x48, 0x8B, 0x05, -1, -1, -1, -1 };
static int vup_sigpatch_vgpusig_new[] = { 0x31, 0xC0, 0x0F, 0x85, -1, -1, -1, -1, 0x48, 0x8B, 0x7D, -1, 0xE8, -1, -1, -1, -1, 0x48, 0x8B, 0x05, -1, -1, -1, -1 };
static struct vup_patch_item vup_diff_vgpusig[] = {
	// based on patch from mbuchel to disable vgpu config signature
	{ vup_sigpatch_vgpusig_old, vup_sigpatch_vgpusig_new, ARRAY_SIZE(vup_sigpatch_vgpusig_old) },
};
VUP_PATCH_DEF(vgpusig, 1, 1, 1);

// Stub a function.
static int vup_sigpatch_kunlock_old1[] = { 0x75, -1, 0x80, 0xBF, -1, -1, -1, -1, -1, 0x75, -1, 0x44, 0x0F, 0xB6, 0xAF, -1, -1, -1, -1 };
static int vup_sigpatch_kunlock_new1[] = { 0xEB, -1, 0x80, 0xBF, -1, -1, -1, -1, -1, 0x75, -1, 0x44, 0x0F, 0xB6, 0xAF, -1, -1, -1, -1 };
// Unconditionally return 1. To avoid spilling outside function, this snapshots the entire thing, which is still fragile.
static int vup_sigpatch_kunlock_old2[] = { 0xF3, 0x0F, 0x1E, 0xFA, 0x48, 0x83, 0xEC, -1, 0x48, 0x81, 0xC7, 0x20, 0x40, 0x00, 0x00, 0x45, 0x31, 0xC0, 0x31, 0xD2, 0xB9, -1, -1, -1, -1, 0x31, 0xF6, 0xE8, -1, -1, -1, -1, 0x48, 0x83, 0xC4, -1, 0xC1, 0xE8, 0x10, 0x83, 0xE0, 0x01, 0xC3 };
static int vup_sigpatch_kunlock_new2[] = { 0xF3, 0x0F, 0x1E, 0xFA, 0x48, 0x83, 0xEC, -1, 0x48, 0x81, 0xC7, 0x20, 0x40, 0x00, 0x00, 0x45, 0x31, 0xC0, 0x31, 0xD2, 0xB9, -1, -1, -1, -1, 0x31, 0xF6, 0xE8, -1, -1, -1, -1, 0x48, 0x83, 0xC4, -1, 0xC1, 0xE8, 0x10, 0x83, 0xC8, 0x01, 0xC3 };
// Unconditionally return 1. To avoid spilling outside function, this snapshots most of it, which is still fragile.
static int vup_sigpatch_kunlock_old3[] = { 0x48, 0x8B, 0xB7, -1, -1, -1, -1, 0xBA, -1, -1, -1, -1, 0xC7, 0x45, -1, -1, -1, -1, -1, 0x48, 0x8D, 0x4D, -1, 0x48, 0x8B, 0x86, -1, -1, -1, -1, 0xE8, -1, -1, -1, -1, 0x8B, 0x45, -1, 0x85, 0xC0, 0x0F, 0x95, 0xC0 };
static int vup_sigpatch_kunlock_new3[] = { 0x48, 0x8B, 0xB7, -1, -1, -1, -1, 0xBA, -1, -1, -1, -1, 0xC7, 0x45, -1, -1, -1, -1, -1, 0x48, 0x8D, 0x4D, -1, 0x48, 0x8B, 0x86, -1, -1, -1, -1, 0xE8, -1, -1, -1, -1, 0x8B, 0x45, -1, 0x85, 0xC0, 0x0F, 0x93, 0xC0 };
// Unconditionally set a field in a struct. This code moved around from R550 to R570 (can be found near the hex literal 0xEBA59CE).
static int vup_sigpatch_kunlock_old4[] = { 0x85, 0xC0, 0x0F, 0x85, -1, -1, -1, -1, 0x80, 0xBB, -1, -1, -1, -1, -1, 0x75, -1, 0x44, 0x0F, 0xB6, 0xB3 };
static int vup_sigpatch_kunlock_new4[] = { 0x90, 0xC7, 0x45, 0x0C, 0x01, -1, -1, -1, 0x80, 0xBB, -1, -1, -1, -1, -1, 0x75, -1, 0x44, 0x0F, 0xB6, 0xB3 };
// Unconditionally set a field in a struct. This signature changed from R550 to R570 (can be found near one string literal "RmIllumLogoBrightness").
static int vup_sigpatch_kunlock_old5[] = { 0x41, 0x80, 0xBC, 0x24, -1, -1, -1, -1, -1, 0x41, 0xC6, 0x84, 0x24, -1, -1, -1, -1, -1, 0x75, -1, 0x41, 0x80, 0xBC, 0x24, -1, -1, -1, -1, -1, 0x0F, 0x84, -1, -1, -1, -1 };
static int vup_sigpatch_kunlock_new5[] = { 0x41, 0x80, 0xBC, 0x24, -1, -1, -1, -1, -1, 0x41, 0xC6, 0x84, 0x24, -1, -1, -1, -1, -1, 0xEB, -1, 0x41, 0x80, 0xBC, 0x24, -1, -1, -1, -1, -1, 0x0F, 0x84, -1, -1, -1, -1 };
// Unconditionally return 1.
static int vup_sigpatch_kunlock_old6[] = { 0x0F, 0xB7, 0x87, -1, -1, -1, -1, 0x83, 0xE0, -1, 0x83, 0xF8, -1 };
static int vup_sigpatch_kunlock_new6[] = { 0x0F, 0xB7, 0x87, -1, -1, -1, -1, 0x83, 0xE0, -1, 0x83, 0xC8, -1 };
static struct vup_patch_item vup_diff_kunlock[] = {
	{ vup_sigpatch_kunlock_old1, vup_sigpatch_kunlock_new1, ARRAY_SIZE(vup_sigpatch_kunlock_old1) },
	{ vup_sigpatch_kunlock_old2, vup_sigpatch_kunlock_new2, ARRAY_SIZE(vup_sigpatch_kunlock_old2) },
	{ vup_sigpatch_kunlock_old3, vup_sigpatch_kunlock_new3, ARRAY_SIZE(vup_sigpatch_kunlock_old3) },
	{ vup_sigpatch_kunlock_old4, vup_sigpatch_kunlock_new4, ARRAY_SIZE(vup_sigpatch_kunlock_old4) },
	{ vup_sigpatch_kunlock_old5, vup_sigpatch_kunlock_new5, ARRAY_SIZE(vup_sigpatch_kunlock_old5) },
	{ vup_sigpatch_kunlock_old6, vup_sigpatch_kunlock_new6, ARRAY_SIZE(vup_sigpatch_kunlock_old6) },
};
VUP_PATCH_DEF(kunlock, 1, 1, 1);

// Invert "feeb3241" *and* a struct comparison in the same if-statement. One of the changes is the jump operand "0x0D" -> "0x07".
static int vup_sigpatch_qmode_old[] = { 0x75, 0x0D, 0x81, 0x7D, -1, -1, -1, -1, -1, 0x0F, 0x84, -1, -1, -1, -1, 0x48, 0x8D, 0x55, -1 };
static int vup_sigpatch_qmode_new[] = { 0x75, 0x07, 0x81, 0x7D, -1, -1, -1, -1, -1, 0x0F, 0x85, -1, -1, -1, -1, 0x48, 0x8D, 0x55, -1 };
static struct vup_patch_item vup_diff_qmode[] = {
	{ vup_sigpatch_qmode_old, vup_sigpatch_qmode_new, ARRAY_SIZE(vup_sigpatch_qmode_old) },
};
VUP_PATCH_DEF(qmode, 0, 0, 1);

// Ignore a struct field. This code moved around from R550 to R570 (can be found near one string literal "RmForceGridDisplayless").
static int vup_sigpatch_merged_old1[] = { 0x41, 0x80, 0xBC, 0x24, -1, -1, -1, -1, -1, 0x74, -1, 0xC6, 0x03, -1 };
static int vup_sigpatch_merged_new1[] = { 0x41, 0x80, 0xBC, 0x24, -1, -1, -1, -1, -1, 0xEB, -1, 0xC6, 0x03, -1 };
// Ignore a struct field by nopping the jump.
static int vup_sigpatch_merged_old2[] = { 0x80, 0xBF, -1, -1, -1, -1, -1, 0x75, 0x2A, 0x48, 0x8D, 0x55, -1, 0x48, 0xC7, 0xC6, -1, -1, -1, -1, 0xE8, -1, -1, -1, -1 };
static int vup_sigpatch_merged_new2[] = { 0x80, 0xBF, -1, -1, -1, -1, -1, 0x90, 0x90, 0x48, 0x8D, 0x55, -1, 0x48, 0xC7, 0xC6, -1, -1, -1, -1, 0xE8, -1, -1, -1, -1 };
static struct vup_patch_item vup_diff_merged[] = {
	{ vup_sigpatch_merged_old1, vup_sigpatch_merged_new1, ARRAY_SIZE(vup_sigpatch_merged_old1) },
	{ vup_sigpatch_merged_old2, vup_sigpatch_merged_new2, ARRAY_SIZE(vup_sigpatch_merged_old2) },
};
VUP_PATCH_DEF(merged, VUP_MERGED_DRIVER, 1, 1);

// This patch is fairly aesthetic: it skips printing the failure message and advances to the function return - up next. Patch target is the jump operand "0x9A" -> "0xBB". However, R570 has an enhancement: if two fields in the struct are the same, it can return success anyways. It remains to be seen if this helps. Note that the function signature and struct changed from R550 to R570.
static int vup_sigpatch_swrlwar_old1[] = { 0x45, 0x85, 0xED, 0x0F, 0x85, 0x9A, -1, -1, -1, 0x41, 0x83, 0xFC, -1, 0x8B, 0x8B, -1, -1, -1, -1 };
static int vup_sigpatch_swrlwar_new1[] = { 0x45, 0x85, 0xED, 0x0F, 0x85, 0xBB, -1, -1, -1, 0x41, 0x83, 0xFC, -1, 0x8B, 0x8B, -1, -1, -1, -1 };
// Unconditionally return success, not failure. Again, note that the function signature and struct changed from R550 to R570.
static int vup_sigpatch_swrlwar_old2[] = { 0x44, 0x89, 0xE8, 0x5B, 0x41, 0x5C, 0x41, 0x5D, 0xC3, 0x66, 0x0F, 0x1F, 0x44, 0x00, -1, 0x44, 0x89, 0xE2 };
static int vup_sigpatch_swrlwar_new2[] = { 0x90, 0x31, 0xC0, 0x5B, 0x41, 0x5C, 0x41, 0x5D, 0xC3, 0x66, 0x0F, 0x1F, 0x44, 0x00, -1, 0x44, 0x89, 0xE2 };
static struct vup_patch_item vup_diff_swrlwar[] = {
	{ vup_sigpatch_swrlwar_old1, vup_sigpatch_swrlwar_new1, ARRAY_SIZE(vup_sigpatch_swrlwar_old1) },
	{ vup_sigpatch_swrlwar_old2, vup_sigpatch_swrlwar_new2, ARRAY_SIZE(vup_sigpatch_swrlwar_old2) },
};
VUP_PATCH_DEF(swrlwar, 0, 1, 1);

// Ignore a result of an `os_is_vgx_hyper()` call in RmInitAdapter().
static int vup_sigpatch_fbcon_old[] = { 0x84, 0xC0, 0x75, -1, 0x41, 0x80, 0xBF, -1, -1, -1, -1, -1, 0x75, -1, 0x49, 0x8B, 0x87, -1 };
static int vup_sigpatch_fbcon_new[] = { 0x30, 0xC0, 0x75, -1, 0x41, 0x80, 0xBF, -1, -1, -1, -1, -1, 0x75, -1, 0x49, 0x8B, 0x87, -1 };
static struct vup_patch_item vup_diff_fbcon[] = {
	{ vup_sigpatch_fbcon_old, vup_sigpatch_fbcon_new, ARRAY_SIZE(vup_sigpatch_fbcon_old) },
};
VUP_PATCH_DEF(fbcon, 1, 1, 1);

// Return 0 instead of 1 in one case of a struct field set by changing the move operand. This function appears to check DIDs to determine return value.
static int vup_sigpatch_sunlock_old1[] = { 0x41, 0xBD, 0x01, -1, -1, -1, 0x5B, 0x44, 0x89, 0xE8, 0x41, 0x5D };
static int vup_sigpatch_sunlock_new1[] = { 0x41, 0xBD, 0x00, -1, -1, -1, 0x5B, 0x44, 0x89, 0xE8, 0x41, 0x5D };
// Set argument to 3, one of the success values, not 0. This signature changed from R550 to R570 (can be found near one of the earlier few XREFs to the above function).
static int vup_sigpatch_sunlock_old2[] = { 0xC7, 0x03, 0x00, -1, -1, -1, 0x31, 0xC0, 0xEB, -1, 0x66, 0x0F, 0x1F, 0x44, 0x00, -1, 0xC7, 0x03, -1, -1, -1, -1 };
static int vup_sigpatch_sunlock_new2[] = { 0xC7, 0x03, 0x03, -1, -1, -1, 0x31, 0xC0, 0xEB, -1, 0x66, 0x0F, 0x1F, 0x44, 0x00, -1, 0xC7, 0x03, -1, -1, -1, -1 };
// Ignore the return value of the first function signature here by nopping the jump. This signature changed from R550 to R570 (can be found near one of the final few XREFs to the above function).
static int vup_sigpatch_sunlock_old3[] = { 0x84, 0xC0, 0x74, 0x4E, 0x49, 0x8B, 0x85, -1, -1, -1, -1, 0x0F, 0xB6, 0x13 };
static int vup_sigpatch_sunlock_new3[] = { 0x84, 0xC0, 0x90, 0x90, 0x49, 0x8B, 0x85, -1, -1, -1, -1, 0x0F, 0xB6, 0x13 };
// Do not set BIT4 in some struct field. This signature appears durable.
static int vup_sigpatch_sunlock_old4[] = { 0x41, 0x83, 0x8C, 0x24, -1, -1, -1, -1, 0x10, 0xE9, -1, -1, -1, -1 };
static int vup_sigpatch_sunlock_new4[] = { 0x41, 0x83, 0x8C, 0x24, -1, -1, -1, -1, 0x00, 0xE9, -1, -1, -1, -1 };
static struct vup_patch_item vup_diff_sunlock[] = {
	{ vup_sigpatch_sunlock_old1, vup_sigpatch_sunlock_new1, ARRAY_SIZE(vup_sigpatch_sunlock_old1) },
	{ vup_sigpatch_kunlock_old1, vup_sigpatch_kunlock_new1, ARRAY_SIZE(vup_sigpatch_kunlock_old1) },
	{ vup_sigpatch_sunlock_old2, vup_sigpatch_sunlock_new2, ARRAY_SIZE(vup_sigpatch_sunlock_old2) },
	{ vup_sigpatch_sunlock_old3, vup_sigpatch_sunlock_new3, ARRAY_SIZE(vup_sigpatch_sunlock_old3) },

	// based on patch from LIL'pingu fixing xid 43 crashes
	{ vup_sigpatch_sunlock_old4, vup_sigpatch_sunlock_new4, ARRAY_SIZE(vup_sigpatch_sunlock_old4) },
};
VUP_PATCH_DEF(sunlock, 0, 1, 1);

// Unconditionally set return value. This signature changed from R550 to R570 (it's the first of three functions called by rm_set_rm_firmware_requested() where the stack is checked).
static int vup_sigpatch_gspvgpu_old1[] = { 0x41, 0x83, 0xFD, 0x01, 0x41, 0x0F, 0x94, 0xC6, 0x45, 0x88, 0x34, 0x24 };
static int vup_sigpatch_gspvgpu_new1[] = { 0x90, 0x4D, 0x31, 0xED, 0x41, 0x0F, 0x94, 0xC6, 0x45, 0x88, 0x34, 0x24 };
// Same as above. This signature changed from R550 to R570 (it's the first of three functions called by rm_set_rm_firmware_requested() where the stack is checked).
static int vup_sigpatch_gspvgpu_old2[] = { 0x45, 0x85, 0xED, 0x41, 0x0F, 0x95, 0xC6, 0x45, 0x88, 0x34, 0x24 };
static int vup_sigpatch_gspvgpu_new2[] = { 0x4D, 0x31, 0xED, 0x41, 0x0F, 0x94, 0xC6, 0x45, 0x88, 0x34, 0x24 };
// Ignore the result of a NV2080_CTRL_CMD_VGPU_MGR_INTERNAL_PGPU_ADD_VGPU_TYPE call.
//static int vup_sigpatch_gspvgpu_old3[] = { 0x4C, 0x89, 0xEF, 0x41, 0x89, 0xC4, 0xE8, -1, -1, -1, -1, 0x45, 0x85, 0xE4, 0x0F, 0x85, -1, -1, -1, -1 };
//static int vup_sigpatch_gspvgpu_new3[] = { 0x4C, 0x89, 0xEF, 0x41, 0x89, 0xC4, 0xE8, -1, -1, -1, -1, 0x45, 0x31, 0xE4, 0x0F, 0x85, -1, -1, -1, -1 };
static struct vup_patch_item vup_diff_gspvgpu[] = {
	{ vup_sigpatch_gspvgpu_old1, vup_sigpatch_gspvgpu_new1, ARRAY_SIZE(vup_sigpatch_gspvgpu_old1) },
	{ vup_sigpatch_gspvgpu_old2, vup_sigpatch_gspvgpu_new2, ARRAY_SIZE(vup_sigpatch_gspvgpu_old2) },
	//{ vup_sigpatch_gspvgpu_old3, vup_sigpatch_gspvgpu_new3, ARRAY_SIZE(vup_sigpatch_gspvgpu_old3) },
};
VUP_PATCH_DEF(gspvgpu, 0, 1, 1);

// Ignore `os_is_vgx_hyper() && IS_TURING()` and never enable SR-IOV. This patch is experimental and untested.
static int vup_sigpatch_sriov_old1[] = { 0xE8, -1, -1, -1, -1, 0x84, 0xC0, 0x0F, 0x84, -1, -1, -1, -1, 0x48, 0x89, 0xDF, 0xE8, -1, -1, -1, -1, 0x84, 0xC0, 0x0F, 0x85, -1, -1, -1, -1 };
static int vup_sigpatch_sriov_new1[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xE9, -1, -1, -1, -1 };
static struct vup_patch_item vup_diff_disable_sriov[] = {
	{ vup_sigpatch_sriov_old1, vup_sigpatch_sriov_new1, ARRAY_SIZE(vup_sigpatch_sriov_old1) },
};
VUP_PATCH_DEF(disable_sriov, 1, 1, 0);

struct vup_patch_info *vup_patches[] = {
	VUP_PATCH(vgpusig),
	VUP_PATCH(kunlock),
	VUP_PATCH(qmode),
	VUP_PATCH(merged),
	VUP_PATCH(swrlwar),
	VUP_PATCH(fbcon),
	VUP_PATCH(sunlock),
	VUP_PATCH(gspvgpu),
	VUP_PATCH(disable_sriov),
};

#elif defined(NV_GRID_BUILD)

// Stub a function.
static int vup_sigpatch_kunlock_old1[] = { 0x75, -1, 0x80, 0xBF, -1, -1, -1, -1, -1, 0x75, -1, 0x44, 0x0F, 0xB6, 0xAF, -1, -1, -1, -1 };
static int vup_sigpatch_kunlock_new1[] = { 0xEB, -1, 0x80, 0xBF, -1, -1, -1, -1, -1, 0x75, -1, 0x44, 0x0F, 0xB6, 0xAF, -1, -1, -1, -1 };
// Conditionally raises the limit on "UnlicensedUnrestrictedStateTimeout" to the default "UnlicensedRestricted1StateTimeout" by changing the move operand. This signature changed from R550 to R570.
static int vup_sigpatch_general_old1[] = { 0x83, 0xFF, 0x14, 0xBF, 0x14, 0x00, -1, -1, 0x48, 0x0F, 0x43, 0xCF };
static int vup_sigpatch_general_new1[] = { 0x83, 0xFF, 0x14, 0xBF, 0xA0, 0x05, -1, -1, 0x48, 0x0F, 0x43, 0xCF };
static int vup_sigpatch_general_old2[] = { 0x41, 0x81, 0xE4, -1, -1, -1, -1, 0x75, -1, 0xE8, -1, -1, -1, -1 };
static int vup_sigpatch_general_new2[] = { 0x41, 0x81, 0xE4, -1, -1, -1, -1, 0xEB, -1, 0xE8, -1, -1, -1, -1 };
static struct vup_patch_item vup_diff_general[] = {
	{ vup_sigpatch_kunlock_old1, vup_sigpatch_kunlock_new1, ARRAY_SIZE(vup_sigpatch_kunlock_old1) },
	{ vup_sigpatch_general_old1, vup_sigpatch_general_new1, ARRAY_SIZE(vup_sigpatch_general_old1) },
	{ vup_sigpatch_general_old2, vup_sigpatch_general_new2, ARRAY_SIZE(vup_sigpatch_general_old2) },
};
VUP_PATCH_DEF(general, 0, 1, 1);

// Ignore `os_is_vgx_hyper() && IS_TURING()` and never enable SR-IOV. This patch is experimental and untested.
static int vup_sigpatch_sriov_old1[] = { 0xE8, -1, -1, -1, -1, 0x84, 0xC0, 0x0F, 0x84, -1, -1, -1, -1, 0x48, 0x89, 0xDF, 0xE8, -1, -1, -1, -1, 0x84, 0xC0, 0x0F, 0x85, -1, -1, -1, -1 };
static int vup_sigpatch_sriov_new1[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xE9, -1, -1, -1, -1 };
static struct vup_patch_item vup_diff_disable_sriov[] = {
	{ vup_sigpatch_sriov_old1, vup_sigpatch_sriov_new1, ARRAY_SIZE(vup_sigpatch_sriov_old1) },
};
VUP_PATCH_DEF(disable_sriov, 1, 1, 0);

struct vup_patch_info *vup_patches[] = {
	VUP_PATCH(general),
	VUP_PATCH(disable_sriov),
};

#endif

// A custom and primitive `memmem()` implementation.
// - TODO: Optimising with some kind of jump search would be nice, probably still possible even with -1, but not necessary.
static uint8_t *find_sigpatch_needle(uint8_t *haystack, size_t haystacklen, int *needle, size_t needlelen)
{
	size_t matched_bytes = 0;
	for (int i = 0; i < haystacklen; i++) {
		if (matched_bytes == needlelen)
			return haystack + i - needlelen;

		if (needle[matched_bytes] == -1 || haystack[i] == needle[matched_bytes])
			matched_bytes++;
		else
			matched_bytes = 0;
	}

	return NULL;
}

static void sigpatch_blob(uint8_t *found_needle, int *newsig, size_t length)
{
	for (int i = 0; i < length; i++) {
		if (newsig[i] != -1)
			found_needle[i] = newsig[i];
	}
}

static void vup_apply_patches(uint8_t *blob_base, size_t blob_size)
{
	int i, j, arg, size;
	struct vup_patch_info *pi;
	uint8_t *item_start;
	const char *name;
	char logbuf[256];

	logbuf[0] = '\0';
	for (i = 0; i < ARRAY_SIZE(vup_patches); i++) {
		pi = vup_patches[i];
		if (vup_vgpukvm_opt == 0 && pi->ovgpu)
			continue;
		j = strlen(logbuf);
		size = sizeof(logbuf) - j;
		arg = *(int *)pi->param->arg;
		name = pi->param->name;
		if (strncmp(name, "vup_", 4) == 0)
			name += 4;
		j = snprintf(logbuf + j, size, arg < 10 ? " %s=%d" : " %s=0x%x",
			     name, arg);
		if (j >= size)
			printk(KERN_WARNING "nvidia: vup_apply_patches "
			       "logbuf too small (%s)\n", name);
		if (arg != pi->enabv)
			continue;

		for (j = 0; j < pi->count; j++) {
			item_start = find_sigpatch_needle(blob_base, blob_size, pi->items[j].oldsig, pi->items[j].length);
			if (item_start == NULL) {
				printk(KERN_ERR "nvidia: vup_apply_patches %s failed (%d)\n", name, j);
				continue;
			}

			sigpatch_blob(item_start, pi->items[j].newsig, pi->items[j].length);
		}
	}
	printk(KERN_INFO "nvidia: vup_apply_patches%s\n", logbuf);
}


/* Entry */

static inline void vup_set_cr0(unsigned long val)
{
	asm volatile("mov %0, %%cr0" : "+r"(val) : : "memory");
}

static inline void vup_set_cr4(unsigned long val)
{
	asm volatile("mov %0, %%cr4" : "+r"(val) : : "memory");
}

static int vup_patching_start(void)
{
	preempt_disable();
	barrier();
	unsigned long cr4 = __read_cr4();
	vup_cr4_cet_enabled = test_bit(X86_CR4_CET_BIT, &cr4);
	if (vup_cr4_cet_enabled) {
		clear_bit(X86_CR4_CET_BIT, &cr4);
		vup_set_cr4(cr4);
		barrier();
	}
	unsigned long cr0 = read_cr0();
	clear_bit(16, &cr0);
	vup_set_cr0(cr0);
	barrier();
	cr0 = read_cr0();
	if (test_bit(16, &cr0) != 0)
		return 0;
	return 1;
}

static void vup_patching_done(void)
{
	unsigned long cr0 = read_cr0();
	set_bit(16, &cr0);
	vup_set_cr0(cr0);
	barrier();
	if (vup_cr4_cet_enabled) {
		unsigned long cr4 = __read_cr4();
		set_bit(X86_CR4_CET_BIT, &cr4);
		vup_set_cr4(cr4);
		barrier();
	}
	preempt_enable_no_resched();
}

void vup_hooks_init(void)
{
	uint8_t *blob = (uint8_t *)rm_ioctl - RM_IOCTL_OFFSET;

#if defined(NV_VGPU_KVM_BUILD)
	vup_vgpukvm_opt = nv_vgpu_kvm_enable;
#elif defined(NV_GRID_BUILD)
	vup_vgpukvm_opt = vup_gridext;
#endif

	if (vup_patching_start()) {
#if 0
		vup_inject_hooks(blob);
		if (vup_vupdevid == 0)
			vup_vupdevid = 0x1e30;
#endif
		vup_apply_patches(blob - 0x40, BLOB_TEXT_SIZE);
	}
	vup_patching_done();
}

void vup_hooks_exit(void) { }
