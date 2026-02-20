#include <linux/mm.h>
#include <linux/module.h>
#include <linux/preempt.h>
#include "nv-linux.h"

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


/* Globals */

#ifndef VUP_MERGED_DRIVER
#define VUP_MERGED_DRIVER 0
#endif

// TODO: Find some way to do this dynamically.
#if defined(NV_VGPU_KVM_BUILD)
#define RM_IOCTL_OFFSET	0xd5f5d0
#define BLOB_TEXT_SIZE	0xe78274
#elif defined(NV_GRID_BUILD)
#define RM_IOCTL_OFFSET	0xd5fc30
#define BLOB_TEXT_SIZE	0xe788d4
#endif

#if defined(NV_GRID_BUILD)
static int vup_gridext = 1;
module_param_named(gridext, vup_gridext, int, 0400);
#endif
static int vup_vgpukvm_opt;
static int vup_cr4_cet_enabled;


/* A primitive `memmem()` implementation customised for finding function signature needles.
   - TODO: Optimising with some kind of jump search would be nice, probably still possible even with -1, but not necessary. */
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


/* VUP hooks */

struct vup_hook_item {
	int *sig;
	size_t patched_instrlen;
	size_t siglen;
	void (*func)(void);
};

struct vup_hook_info {
	const struct kernel_param *param;
	struct vup_hook_item *item;
	int ovgpu;
};

#define VUP_HOOK_DEF(name, vgpuopt) \
static struct vup_hook_info vup_hook_info_##name = { \
	.param = &__param_##name, \
	.item  = &vup_diff_##name, \
	.ovgpu = vgpuopt, \
}
#define VUP_HOOK(name) &vup_hook_info_##name

#if defined(NV_VGPU_KVM_BUILD)
static int vup_cudahost = VUP_MERGED_DRIVER;
module_param_named(cudahost, vup_cudahost, int, 0400);

__attribute__((used))
static void vup_hook_cudahost(uint8_t *flag)
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
		"endbr64                \n"
		"push   %rdi            \n"
		"push   %rsi            \n"
		"push   %rdx            \n"
		"push   %rcx            \n"
		"push   %r8             \n"
		"push   %r9             \n"
		// Load a pointer to the field being checked next. This is the actual target.
		"lea   0x42c(%r13), %rdi\n"
		"call  vup_hook_cudahost\n"
		"pop    %r9             \n"
		"pop    %r8             \n"
		"pop    %rcx            \n"
		"pop    %rdx            \n"
		"pop    %rsi            \n"
		"pop    %rdi            \n"
		// Copy in the replaced instruction(s).
		"cmpb   $0, 0x968(%r14) \n"
		ASM_RET
	);
}
STACK_FRAME_NON_STANDARD(vup_hook_cudahost_naked);

// There have been significant changes here since R550: now, functions are added to an object that's passed as an argument. The fastest way to find this is to search for the immediate value `0xE7D23F1`, the first argument to the 'debug'/'assert' function (probably mapping to the source file), and look for a function about 512 bytes large with 3-5 instances of it.
static int vup_sighook_cudahost[] = { 0x41, 0x80, 0xBE, -1, -1, -1, -1, -1, 0x74, -1, 0x41, 0x80, 0xBD, -1, -1, -1, -1, -1, 0x74, -1, 0x41, 0xC6, 0x85, -1, -1, -1, -1, -1 };
static struct vup_hook_item vup_diff_cudahost = {
	vup_sighook_cudahost, 8, ARRAY_SIZE(vup_sighook_cudahost), vup_hook_cudahost_naked
};
VUP_HOOK_DEF(cudahost, 1);
#endif

static int vup_vupdevid = 0x1e30;
module_param_named(vupdevid, vup_vupdevid, int, 0400);

__attribute__((used))
static uint32_t vup_hook_vupdevid(uint32_t devid, uint32_t subdevid)
{
	printk(KERN_INFO "nvidia: vup_hook vupdevid=0x%04x devid=0x10de:0x%04x subdevid=0x%04x:0x%04x\n",
	       vup_vupdevid, devid, subdevid & 0xffff, subdevid >> 16);
	return vup_vupdevid;
}

__attribute__((naked, no_instrument_function, no_stack_protector,
               no_split_stack, noclone, function_return("keep")))
static void vup_hook_vupdevid_naked(void)
{
	asm (
		"endbr64                \n"
		"push   %rdi            \n"
		"push   %rsi            \n"
		"push   %rdx            \n"
		"push   %rcx            \n"
		"push   %r8             \n"
		"push   %r9             \n"
		// The earlier of two struct fields read into local variables above is the devid.
		"mov    %r15, %rdi      \n"
		// The latter of two struct fields read into local variables above is the subdevid.
		// - Two bytes before it gets the vendor ID too.
		"mov   0xcf4(%r14), %esi\n"
		"call  vup_hook_vupdevid\n"
		// If the return value is non-zero, overwrite the above.
		"test   %eax, %eax      \n"
		"cmovne %eax, %r15d     \n"
		// Also override an above function's result. This influences operations against a struct of enum'd device IDs.
		"mov    $1, %r13d       \n"
		"pop    %r9             \n"
		"pop    %r8             \n"
		"pop    %rcx            \n"
		"pop    %rdx            \n"
		"pop    %rsi            \n"
		"pop    %rdi            \n"
		// Copy in the replaced instruction(s).
		"mov    %r12, %rax      \n"
		"mov    %r15d, %ebx     \n"
		ASM_RET
	);
}
STACK_FRAME_NON_STANDARD(vup_hook_vupdevid_naked);

// This signature seems to be durable.
static int vup_sighook_vupdevid[] = { 0x4C, 0x89, 0xE0, 0x44, 0x89, 0xFB };
static struct vup_hook_item vup_diff_vupdevid = {
	vup_sighook_vupdevid, 6, ARRAY_SIZE(vup_sighook_vupdevid), vup_hook_vupdevid_naked
};
VUP_HOOK_DEF(vupdevid, 1);

// TODO: Consider implementing klogtrace support for Linux.

#if 0

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
		"endbr64                \n"
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
		ASM_RET
	);
}
STACK_FRAME_NON_STANDARD(vup_hook_klogtrace_naked);

// This is at 0x00016185 in 550.90.
static int vup_sighook_klogtrace[] = { 0x48, 0x81, 0xED, 0x40, 0x04, 0x00, 0x00 };
static struct vup_hook_item vup_diff_klogtrace = {
	vup_sighook_klogtrace, 7, ARRAY_SIZE(vup_sighook_klogtrace), vup_hook_klogtrace_naked
};
VUP_HOOK_DEF(klogtrace, 0);

#endif

static struct vup_hook_info *vup_hooks[] = {
#if defined(NV_VGPU_KVM_BUILD)
	VUP_HOOK(cudahost),
	VUP_HOOK(vupdevid),
	//VUP_HOOK(klogtrace),
#elif defined(NV_GRID_BUILD)
	VUP_HOOK(vupdevid),
	//VUP_HOOK(klogtrace),
#endif
};

static void vup_inject_hooks(uint8_t *blob_base, size_t blob_size)
{
	int i, j, arg, size;
	struct vup_hook_info *hi;
	uint8_t *item_start;
	const char *name;
	char logbuf[128];

	logbuf[0] = '\0';
	for (i = 0; i < ARRAY_SIZE(vup_hooks); i++) {
		hi = vup_hooks[i];
		if (vup_vgpukvm_opt == 0 && hi->ovgpu)
			continue;
		j = strlen(logbuf);
		size = sizeof(logbuf) - j;
		arg = *(int *)hi->param->arg;
		name = hi->param->name;
		j = snprintf(logbuf + j, size, arg < 10 ? " %s=%d" : " %s=0x%x",
			     name, arg);
		if (j >= size)
			printk(KERN_WARNING "nvidia: vup_inject_hooks "
			       "logbuf too small (%s)\n", name);
		if (arg < 0)
			continue;

		item_start = find_sigpatch_needle(blob_base, blob_size, hi->item->sig, hi->item->siglen);
		if (item_start == NULL) {
			printk(KERN_ERR "nvidia: vup_inject_hooks %s failed (%d)\n", name, j);
			continue;
		}

		*item_start = 0xe8;
		*(uint32_t *)(item_start + 1) =
			(uint8_t *)hi->item->func - (item_start + 5);
		for (j = 5; j < hi->item->patched_instrlen; j++)
			*(item_start + j) = 0x90;
	}
	printk(KERN_INFO "nvidia: vup_inject_hooks cetbit=%d%s\n",
	       vup_cr4_cet_enabled, logbuf);
}


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

// Ignore the return value of the `os_mem_cmp()` thunk in the function that also calls one with string references to licenses - "NVIDIA Virtual PC", etc.
static int vup_sigpatch_vgpusig_old[] = { 0x85, 0xC0, 0x0F, 0x85, -1, -1, -1, -1, 0x48, 0x8B, 0x7D, -1, 0xE8, -1, -1, -1, -1, 0x48, 0x8B, 0x05, -1, -1, -1, -1 };
static int vup_sigpatch_vgpusig_new[] = { 0x31, 0xC0, 0x0F, 0x85, -1, -1, -1, -1, 0x48, 0x8B, 0x7D, -1, 0xE8, -1, -1, -1, -1, 0x48, 0x8B, 0x05, -1, -1, -1, -1 };
static struct vup_patch_item vup_diff_vgpusig[] = {
	// based on a patch from mbuchel to disable vgpu config signature
	{ vup_sigpatch_vgpusig_old, vup_sigpatch_vgpusig_new, ARRAY_SIZE(vup_sigpatch_vgpusig_old) },
};
VUP_PATCH_DEF(vgpusig, 1, 1, 1);

// Stub a function. This signature seems to be durable.
static int vup_sigpatch_kunlock_old0[] = { 0x75, -1, 0x80, 0xBF, -1, -1, -1, -1, -1, 0x75, -1, 0x44, 0x0F, 0xB6, 0xAF, -1, -1, -1, -1 };
static int vup_sigpatch_kunlock_new0[] = { 0xEB, -1, 0x80, 0xBF, -1, -1, -1, -1, -1, 0x75, -1, 0x44, 0x0F, 0xB6, 0xAF, -1, -1, -1, -1 };
// Unconditionally return 1. To avoid spilling outside function, this snapshotted the entire thing, which is still fragile. The fastest way to find this was to search for the immediate value `0xED01339`, the first argument to the 'debug'/'assert' function (probably mapping to the source file), and look for a function about 512 bytes large with 1-2 instances of it. Then, go back to the XREF that passes it as a function argument. However, this XREF is no longer present, only the other remains.
static int vup_sigpatch_kunlock_old1[] = { 0xF3, 0x0F, 0x1E, 0xFA, 0x48, 0x83, 0xEC, -1, 0x48, 0x81, 0xC7, 0x20, 0x40, 0x00, 0x00, 0x45, 0x31, 0xC0, 0x31, 0xD2, 0xB9, -1, -1, -1, -1, 0x31, 0xF6, 0xE8, -1, -1, -1, -1, 0x48, 0x83, 0xC4, -1, 0xC1, 0xE8, 0x10, 0x83, 0xE0, 0x01, 0xC3 };
static int vup_sigpatch_kunlock_new1[] = { 0xF3, 0x0F, 0x1E, 0xFA, 0x48, 0x83, 0xEC, -1, 0x48, 0x81, 0xC7, 0x20, 0x40, 0x00, 0x00, 0x45, 0x31, 0xC0, 0x31, 0xD2, 0xB9, -1, -1, -1, -1, 0x31, 0xF6, 0xE8, -1, -1, -1, -1, 0x48, 0x83, 0xC4, -1, 0xC1, 0xE8, 0x10, 0x83, 0xC8, 0x01, 0xC3 };
// Unconditionally return 1. To avoid spilling outside function, this snapshots most of it, which is still fragile.
static int vup_sigpatch_kunlock_old2[] = { 0x48, 0x8B, 0xB7, -1, -1, -1, -1, 0xBA, -1, -1, -1, -1, 0xC7, 0x45, -1, -1, -1, -1, -1, 0x48, 0x8D, 0x4D, -1, 0x48, 0x8B, 0x86, -1, -1, -1, -1, 0xE8, -1, -1, -1, -1, 0x8B, 0x45, -1, 0x85, 0xC0, 0x0F, 0x95, 0xC0 };
static int vup_sigpatch_kunlock_new2[] = { 0x48, 0x8B, 0xB7, -1, -1, -1, -1, 0xBA, -1, -1, -1, -1, 0xC7, 0x45, -1, -1, -1, -1, -1, 0x48, 0x8D, 0x4D, -1, 0x48, 0x8B, 0x86, -1, -1, -1, -1, 0xE8, -1, -1, -1, -1, 0x8B, 0x45, -1, 0x85, 0xC0, 0x0F, 0x93, 0xC0 };
// Unconditionally set a field in a struct. This code moved around from R550 to R570 (can be found near the hex literal 0xEBA59CE).
static int vup_sigpatch_kunlock_old3[] = { 0x85, 0xC0, 0x0F, 0x85, -1, -1, -1, -1, 0x80, 0xBB, -1, -1, -1, -1, -1, 0x75, -1, 0x44, 0x0F, 0xB6, 0xB3 };
static int vup_sigpatch_kunlock_new3[] = { 0x90, 0xC7, 0x45, 0x0C, 0x01, -1, -1, -1, 0x80, 0xBB, -1, -1, -1, -1, -1, 0x75, -1, 0x44, 0x0F, 0xB6, 0xB3 };
// Unconditionally set a field in a struct. This signature changed from R550 to R570 (can be found near one string literal "RmIllumLogoBrightness").
// - This looks like a registry DWord. Consider if this can be set-up instead of patching the code.
static int vup_sigpatch_kunlock_old4[] = { 0x41, 0x80, 0xBC, 0x24, -1, -1, -1, -1, -1, 0x41, 0xC6, 0x84, 0x24, -1, -1, -1, -1, -1, 0x75, -1, 0x41, 0x80, 0xBC, 0x24, -1, -1, -1, -1, -1, 0x0F, 0x84, -1, -1, -1, -1 };
static int vup_sigpatch_kunlock_new4[] = { 0x41, 0x80, 0xBC, 0x24, -1, -1, -1, -1, -1, 0x41, 0xC6, 0x84, 0x24, -1, -1, -1, -1, -1, 0xEB, -1, 0x41, 0x80, 0xBC, 0x24, -1, -1, -1, -1, -1, 0x0F, 0x84, -1, -1, -1, -1 };
// Unconditionally return 1.
static int vup_sigpatch_kunlock_old5[] = { 0x0F, 0xB7, 0x87, -1, -1, -1, -1, 0x83, 0xE0, -1, 0x83, 0xF8, -1 };
static int vup_sigpatch_kunlock_new5[] = { 0x0F, 0xB7, 0x87, -1, -1, -1, -1, 0x83, 0xE0, -1, 0x83, 0xC8, -1 };
static struct vup_patch_item vup_diff_kunlock[] = {
	{ vup_sigpatch_kunlock_old0, vup_sigpatch_kunlock_new0, ARRAY_SIZE(vup_sigpatch_kunlock_old0) },
	{ vup_sigpatch_kunlock_old1, vup_sigpatch_kunlock_new1, ARRAY_SIZE(vup_sigpatch_kunlock_old1) }, // FIXME/BUGBUG: Broken.
	{ vup_sigpatch_kunlock_old2, vup_sigpatch_kunlock_new2, ARRAY_SIZE(vup_sigpatch_kunlock_old2) }, // FIXME/BUGBUG: Broken?!
	{ vup_sigpatch_kunlock_old3, vup_sigpatch_kunlock_new3, ARRAY_SIZE(vup_sigpatch_kunlock_old3) },
	{ vup_sigpatch_kunlock_old4, vup_sigpatch_kunlock_new4, ARRAY_SIZE(vup_sigpatch_kunlock_old4) }, // FIXME/BUGBUG: Broken?!
	{ vup_sigpatch_kunlock_old5, vup_sigpatch_kunlock_new5, ARRAY_SIZE(vup_sigpatch_kunlock_old5) },
};
VUP_PATCH_DEF(kunlock, 1, 1, 1); // FIXME: Investigate *how* this works.

// This enables the 'force Quadro as GeForce' behaviour by inverting the read of the "feeb3241" registry DWord *and* a struct comparison in the same if-statement. One of the changes is the jump operand "0x0D" -> "0x07".
// - Consider if this can be set-up instead of patching the code.
static int vup_sigpatch_qmode_old[] = { 0x75, 0x0D, 0x81, 0x7D, -1, -1, -1, -1, -1, 0x0F, 0x84, -1, -1, -1, -1, 0x48, 0x8D, 0x55, -1 };
static int vup_sigpatch_qmode_new[] = { 0x75, 0x07, 0x81, 0x7D, -1, -1, -1, -1, -1, 0x0F, 0x85, -1, -1, -1, -1, 0x48, 0x8D, 0x55, -1 };
static struct vup_patch_item vup_diff_qmode[] = {
	{ vup_sigpatch_qmode_old, vup_sigpatch_qmode_new, ARRAY_SIZE(vup_sigpatch_qmode_old) },
};
VUP_PATCH_DEF(qmode, 0, 0, 1);

// Ignore a struct field. This code moved around from R550 to R570 (can be found near one string literal "RmForceGridDisplayless").
// - Consider if this can be set-up instead of patching the code.
static int vup_sigpatch_merged_old0[] = { 0x41, 0x80, 0xBC, 0x24, -1, -1, -1, -1, -1, 0x74, -1, 0xC6, 0x03, -1 };
static int vup_sigpatch_merged_new0[] = { 0x41, 0x80, 0xBC, 0x24, -1, -1, -1, -1, -1, 0xEB, -1, 0xC6, 0x03, -1 };
// Ignore a struct field by nopping the jump.
static int vup_sigpatch_merged_old1[] = { 0x80, 0xBF, -1, -1, -1, -1, -1, 0x75, 0x2A, 0x48, 0x8D, 0x55, -1, 0x48, 0xC7, 0xC6, -1, -1, -1, -1, 0xE8, -1, -1, -1, -1 };
static int vup_sigpatch_merged_new1[] = { 0x80, 0xBF, -1, -1, -1, -1, -1, 0x90, 0x90, 0x48, 0x8D, 0x55, -1, 0x48, 0xC7, 0xC6, -1, -1, -1, -1, 0xE8, -1, -1, -1, -1 };
static struct vup_patch_item vup_diff_merged[] = {
	{ vup_sigpatch_merged_old0, vup_sigpatch_merged_new0, ARRAY_SIZE(vup_sigpatch_merged_old0) },
	{ vup_sigpatch_merged_old1, vup_sigpatch_merged_new1, ARRAY_SIZE(vup_sigpatch_merged_old1) }, // FIXME: Investigate *how* this works.
};
VUP_PATCH_DEF(merged, VUP_MERGED_DRIVER, 1, 1);

// This patch is fairly aesthetic: it skips printing the failure message and advances to the function return - up next. Patch target is the jump operand "0x9A" -> "0xBB". However, R570 has an enhancement: if two fields in the struct are the same, it can return success anyways. It remains to be seen if this helps. Note that the function signature and struct changed from R550 to R570.
static int vup_sigpatch_swrlwar_old0[] = { 0x45, 0x85, 0xED, 0x0F, 0x85, 0x9A, -1, -1, -1, 0x41, 0x83, 0xFC, -1, 0x8B, 0x8B, -1, -1, -1, -1 };
static int vup_sigpatch_swrlwar_new0[] = { 0x45, 0x85, 0xED, 0x0F, 0x85, 0xBB, -1, -1, -1, 0x41, 0x83, 0xFC, -1, 0x8B, 0x8B, -1, -1, -1, -1 };
// Unconditionally return success, not failure. Again, note that the function signature and struct changed from R550 to R570.
static int vup_sigpatch_swrlwar_old1[] = { 0x44, 0x89, 0xE8, 0x5B, 0x41, 0x5C, 0x41, 0x5D, 0xC3, 0x66, 0x0F, 0x1F, 0x44, 0x00, -1, 0x44, 0x89, 0xE2 };
static int vup_sigpatch_swrlwar_new1[] = { 0x90, 0x31, 0xC0, 0x5B, 0x41, 0x5C, 0x41, 0x5D, 0xC3, 0x66, 0x0F, 0x1F, 0x44, 0x00, -1, 0x44, 0x89, 0xE2 };
static struct vup_patch_item vup_diff_swrlwar[] = {
	{ vup_sigpatch_swrlwar_old0, vup_sigpatch_swrlwar_new0, ARRAY_SIZE(vup_sigpatch_swrlwar_old0) },
	{ vup_sigpatch_swrlwar_old1, vup_sigpatch_swrlwar_new1, ARRAY_SIZE(vup_sigpatch_swrlwar_old1) },
};
VUP_PATCH_DEF(swrlwar, 0, 1, 1); // FIXME/BUGBUG: Broken.

// Ignore a result of an `os_is_vgx_hyper()` call in RmInitAdapter().
static int vup_sigpatch_fbcon_old[] = { 0x84, 0xC0, 0x75, -1, 0x41, 0x80, 0xBF, -1, -1, -1, -1, -1, 0x75, -1, 0x49, 0x8B, 0x87, -1 };
static int vup_sigpatch_fbcon_new[] = { 0x30, 0xC0, 0x75, -1, 0x41, 0x80, 0xBF, -1, -1, -1, -1, -1, 0x75, -1, 0x49, 0x8B, 0x87, -1 };
static struct vup_patch_item vup_diff_fbcon[] = {
	{ vup_sigpatch_fbcon_old, vup_sigpatch_fbcon_new, ARRAY_SIZE(vup_sigpatch_fbcon_old) },
};
VUP_PATCH_DEF(fbcon, 1, 1, 1);

// Return 0 instead of 1 in one case of a struct field set by changing the move operand. This function appears to check DIDs to determine return value.
static int vup_sigpatch_sunlock_old0[] = { 0x41, 0xBD, 0x01, -1, -1, -1, 0x5B, 0x44, 0x89, 0xE8, 0x41, 0x5D };
static int vup_sigpatch_sunlock_new0[] = { 0x41, 0xBD, 0x00, -1, -1, -1, 0x5B, 0x44, 0x89, 0xE8, 0x41, 0x5D };
// Set argument to 3, one of the success values, not 0. This signature changed from R550 to R570 (can be found near one of the earlier few XREFs to the above function).
static int vup_sigpatch_sunlock_old1[] = { 0xC7, 0x03, 0x00, -1, -1, -1, 0x31, 0xC0, 0xEB, -1, 0x66, 0x0F, 0x1F, 0x44, 0x00, -1, 0xC7, 0x03, -1, -1, -1, -1 };
static int vup_sigpatch_sunlock_new1[] = { 0xC7, 0x03, 0x03, -1, -1, -1, 0x31, 0xC0, 0xEB, -1, 0x66, 0x0F, 0x1F, 0x44, 0x00, -1, 0xC7, 0x03, -1, -1, -1, -1 };
// Ignore the return value of the first function signature here by nopping the jump. This signature changed from R550 to R570 (can be found near one of the final few XREFs to the above function).
static int vup_sigpatch_sunlock_old2[] = { 0x84, 0xC0, 0x74, 0x4E, 0x49, 0x8B, 0x85, -1, -1, -1, -1, 0x0F, 0xB6, 0x13 };
static int vup_sigpatch_sunlock_new2[] = { 0x84, 0xC0, 0x90, 0x90, 0x49, 0x8B, 0x85, -1, -1, -1, -1, 0x0F, 0xB6, 0x13 };
// Do not set BIT4 in some struct field. This signature seems to be durable.
static int vup_sigpatch_sunlock_old3[] = { 0x41, 0x83, 0x8C, 0x24, -1, -1, -1, -1, 0x10, 0xE9, -1, -1, -1, -1 };
static int vup_sigpatch_sunlock_new3[] = { 0x41, 0x83, 0x8C, 0x24, -1, -1, -1, -1, 0x00, 0xE9, -1, -1, -1, -1 };
static struct vup_patch_item vup_diff_sunlock[] = {
	{ vup_sigpatch_sunlock_old0, vup_sigpatch_sunlock_new0, ARRAY_SIZE(vup_sigpatch_sunlock_old0) },
	{ vup_sigpatch_kunlock_old0, vup_sigpatch_kunlock_new0, ARRAY_SIZE(vup_sigpatch_kunlock_old0) },
	{ vup_sigpatch_sunlock_old1, vup_sigpatch_sunlock_new1, ARRAY_SIZE(vup_sigpatch_sunlock_old1) },
	{ vup_sigpatch_sunlock_old2, vup_sigpatch_sunlock_new2, ARRAY_SIZE(vup_sigpatch_sunlock_old2) },

	// based on patch from LIL'pingu fixing xid 43 crashes
	{ vup_sigpatch_sunlock_old3, vup_sigpatch_sunlock_new3, ARRAY_SIZE(vup_sigpatch_sunlock_old3) },
};
VUP_PATCH_DEF(sunlock, 0, 1, 1); // FIXME: Investigate *how* this works.

// Unconditionally set return value and output pointer. Interestingly, this signature changed from R550 to R570, but then changed back in R580 (it's in a function called by rm_set_rm_firmware_requested(), right before it checks the stack).
static int vup_sigpatch_gspvgpu_old0[] = { 0x84, 0xC0, 0x74, -1, 0x83, 0xE3, -1, 0xB8, -1, -1, -1, -1, 0x83, 0xFB, -1, 0x74, -1 };
static int vup_sigpatch_gspvgpu_new0[] = { 0x84, 0xC0, 0x90, 0x90, 0x83, 0xE3, -1, 0xB8, -1, -1, -1, -1, 0x83, 0xFB, -1, 0xEB, -1 };
// Ignore the result of a NV2080_CTRL_CMD_VGPU_MGR_INTERNAL_PGPU_ADD_VGPU_TYPE call.
// - This was commented-out upstream too. This signature was last valid for 580.95.
//static int vup_sigpatch_gspvgpu_old1[] = { 0x4C, 0x89, 0xEF, 0x41, 0x89, 0xC4, 0xE8, -1, -1, -1, -1, 0x45, 0x85, 0xE4, 0x0F, 0x85, -1, -1, -1, -1 };
//static int vup_sigpatch_gspvgpu_new1[] = { 0x4C, 0x89, 0xEF, 0x41, 0x89, 0xC4, 0xE8, -1, -1, -1, -1, 0x45, 0x31, 0xE4, 0x0F, 0x85, -1, -1, -1, -1 };
static struct vup_patch_item vup_diff_gspvgpu[] = {
	{ vup_sigpatch_gspvgpu_old0, vup_sigpatch_gspvgpu_new0, ARRAY_SIZE(vup_sigpatch_gspvgpu_old0) },
	//{ vup_sigpatch_gspvgpu_old1, vup_sigpatch_gspvgpu_new1, ARRAY_SIZE(vup_sigpatch_gspvgpu_old1) },
};
VUP_PATCH_DEF(gspvgpu, 0, 1, 1);

struct vup_patch_info *vup_patches[] = {
	VUP_PATCH(vgpusig),
	VUP_PATCH(kunlock),
	VUP_PATCH(qmode),
	VUP_PATCH(merged),
	VUP_PATCH(swrlwar),
	VUP_PATCH(fbcon),
	VUP_PATCH(sunlock),
	VUP_PATCH(gspvgpu),
};

#elif defined(NV_GRID_BUILD)

// Stub a function. This signature seems to be durable.
static int vup_sigpatch_kunlock_old0[] = { 0x75, -1, 0x80, 0xBF, -1, -1, -1, -1, -1, 0x75, -1, 0x44, 0x0F, 0xB6, 0xAF, -1, -1, -1, -1 };
static int vup_sigpatch_kunlock_new0[] = { 0xEB, -1, 0x80, 0xBF, -1, -1, -1, -1, -1, 0x75, -1, 0x44, 0x0F, 0xB6, 0xAF, -1, -1, -1, -1 };
// (Conditionally) Raises the limit on "UnlicensedUnrestrictedStateTimeout" to that of "UnlicensedRestricted1StateTimeout".
// - This only allows a little longer, use actual licensing (NLS or DLS) instead. This signature was last valid for 580.95.
//static int vup_sigpatch_general_old0[] = { 0x83, 0xFF, 0x14, 0xBF, 0x14, 0x00, -1, -1, 0x48, 0x0F, 0x43, 0xCF };
//static int vup_sigpatch_general_new0[] = { 0x83, 0xFF, 0x14, 0xBF, 0xA0, 0x05, -1, -1, 0x48, 0x0F, 0x43, 0xCF };
//static int vup_sigpatch_general_old1[] = { 0x41, 0x81, 0xE4, -1, -1, -1, -1, 0x75, -1, 0xE8, -1, -1, -1, -1 };
//static int vup_sigpatch_general_new1[] = { 0x41, 0x81, 0xE4, -1, -1, -1, -1, 0xEB, -1, 0xE8, -1, -1, -1, -1 };
static struct vup_patch_item vup_diff_general[] = {
	{ vup_sigpatch_kunlock_old0, vup_sigpatch_kunlock_new0, ARRAY_SIZE(vup_sigpatch_kunlock_old0) },
	//{ vup_sigpatch_general_old0, vup_sigpatch_general_new0, ARRAY_SIZE(vup_sigpatch_general_old0) },
	//{ vup_sigpatch_general_old1, vup_sigpatch_general_new1, ARRAY_SIZE(vup_sigpatch_general_old1) },
};
VUP_PATCH_DEF(general, 0, 1, 1);

struct vup_patch_info *vup_patches[] = {
	VUP_PATCH(general),
};

#endif

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
		vup_inject_hooks(blob, BLOB_TEXT_SIZE);
		vup_apply_patches(blob - 0x40, BLOB_TEXT_SIZE);
	}
	vup_patching_done();
}

void vup_hooks_exit(void) { }
