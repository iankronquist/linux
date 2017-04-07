#include "vmcsctl.h"

static struct kset *vmcsctl_set;
static bool vmxon;

static inline struct vmcsctl *vmcsctl_container_of(struct kobject *kobj)
{
	return container_of(kobj, struct vmcsctl, kobj);
}

static void vmcsctl_release(struct kobject *kobj)
{
	struct vmcsctl *vmcsctl = vmcsctl_container_of(kobj);

	kfree(vmcsctl);
}

static struct kobj_type vmcsctl_kobj_ktype = {
	.release	= vmcsctl_release,
	.sysfs_ops	= &kobj_sysfs_ops,
};

static ssize_t revision_id_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct vmcsctl *vmcsctl = vmcsctl_container_of(kobj);

	WARN_ON(vmcsctl->vmcs == NULL);
	return sprintf(buf, "%d\n", vmcsctl->vmcs->revision_id);
}

static ssize_t abort_show(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct vmcsctl *vmcsctl = vmcsctl_container_of(kobj);

	WARN_ON(vmcsctl->vmcs == NULL);
	return sprintf(buf, "%d\n", vmcsctl->vmcs->abort);
}

static ssize_t vmcs_field_show_u16(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf, enum vmcs_field field)
{
	u16 value;
	struct vmcsctl *vmcsctl = vmcsctl_container_of(kobj);
	struct vmcs *original_vmcs = vmcs_store();

	WARN_ON(vmcsctl->vmcs == NULL);
	vmcs_load(vmcsctl->vmcs);

	value = vmcs_read16(field);
	vmcs_load(original_vmcs);
	return sprintf(buf, "%hu\n", value);
}

static ssize_t vmcs_field_store_u16(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count,
	enum vmcs_field field)
{
	int ret;
	u16 value;
	struct vmcsctl *vmcsctl = vmcsctl_container_of(kobj);
	struct vmcs *original_vmcs = vmcs_store();

	WARN_ON(vmcsctl->vmcs == NULL);
	vmcs_load(vmcsctl->vmcs);

	ret = kstrtou16(buf, 10, &value);
	if (ret < 0)
		return ret;

	vmcs_write16(field, value);
	vmcs_load(original_vmcs);
	return count;
}

static ssize_t vmcs_field_show_u32(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf, enum vmcs_field field)
{
	u32 value;
	struct vmcsctl *vmcsctl = vmcsctl_container_of(kobj);
	struct vmcs *original_vmcs = vmcs_store();

	WARN_ON(vmcsctl->vmcs == NULL);
	vmcs_load(vmcsctl->vmcs);
	value = vmcs_read32(field);
	vmcs_load(original_vmcs);
	return sprintf(buf, "%u\n", value);
}

static ssize_t vmcs_field_store_u32(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count,
	enum vmcs_field field)
{
	int ret;
	u32 value;
	struct vmcsctl *vmcsctl = vmcsctl_container_of(kobj);
	struct vmcs *original_vmcs = vmcs_store();

	WARN_ON(vmcsctl->vmcs == NULL);
	vmcs_load(vmcsctl->vmcs);
	ret = kstrtouint(buf, 10, &value);
	if (ret < 0)
		return ret;

	vmcs_write32(field, value);
	vmcs_load(original_vmcs);
	return count;
}

static ssize_t vmcs_field_show_u64(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf, enum vmcs_field field)
{
	u64 value;
	struct vmcsctl *vmcsctl = vmcsctl_container_of(kobj);
	struct vmcs *original_vmcs = vmcs_store();

	WARN_ON(vmcsctl->vmcs == NULL);
	vmcs_load(vmcsctl->vmcs);
	value = vmcs_read64(field);

	vmcs_load(original_vmcs);
	return sprintf(buf, "%llu\n", value);
}

static ssize_t vmcs_field_store_u64(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count,
	enum vmcs_field field)
{
	int ret;
	u64 value;
	struct vmcsctl *vmcsctl = vmcsctl_container_of(kobj);
	struct vmcs *original_vmcs = vmcs_store();

	vmcs_load(vmcsctl->vmcs);

	WARN_ON(vmcsctl->vmcs == NULL);
	ret = kstrtoull(buf, 10, &value);
	if (ret < 0)
		return ret;

	vmcs_write64(field, value);

	vmcs_load(original_vmcs);
	return count;
}


#ifdef x86_64
#define natural_width u64
#else
#define natural_width u32
#endif

#define VMCS_ATTR_SHOW(attr_field, type) \
static ssize_t vmcs_##attr_field##_show(struct kobject *kobj, \
		struct kobj_attribute *attr, char *buf) \
{ \
	if (vmxon) { \
		return vmcs_field_show_##type(kobj, attr, buf, attr_field); \
	} else { \
		return -1; \
	} \
}

#define VMCS_ATTR_STORE(attr_field, type) \
static ssize_t vmcs_##attr_field##_store(struct kobject *kobj, \
		struct kobj_attribute *attr, const char *buf, size_t count) \
{ \
	if (vmxon) { \
		return vmcs_field_store_##type(kobj, attr, buf, count, \
				attr_field); \
	} else { \
		return -1; \
	} \
}

#define VMCS_ATTR(attr_field, type) \
	VMCS_ATTR_SHOW(attr_field, type) \
	VMCS_ATTR_STORE(attr_field, type) \
	static struct kobj_attribute vmcs_field_##attr_field = \
		__ATTR(attr_field, 0644, vmcs_##attr_field##_show, \
			vmcs_##attr_field##_store)

#define VMCS_ATTR_RO(attr_field, type) \
	VMCS_ATTR_SHOW(attr_field, type) \
	static struct kobj_attribute vmcs_field_##attr_field = \
		__ATTR(attr_field, 0444, vmcs_##attr_field##_show, \
			NULL)

VMCS_ATTR(VIRTUAL_PROCESSOR_ID, u16);
VMCS_ATTR(POSTED_INTR_NV, u16);
VMCS_ATTR(GUEST_ES_SELECTOR, u16);
VMCS_ATTR(GUEST_CS_SELECTOR, u16);
VMCS_ATTR(GUEST_SS_SELECTOR, u16);
VMCS_ATTR(GUEST_DS_SELECTOR, u16);
VMCS_ATTR(GUEST_FS_SELECTOR, u16);
VMCS_ATTR(GUEST_GS_SELECTOR, u16);
VMCS_ATTR(GUEST_LDTR_SELECTOR, u16);
VMCS_ATTR(GUEST_TR_SELECTOR, u16);
VMCS_ATTR(GUEST_INTR_STATUS, u16);
VMCS_ATTR(GUEST_PML_INDEX, u16);
VMCS_ATTR(HOST_ES_SELECTOR, u16);
VMCS_ATTR(HOST_CS_SELECTOR, u16);
VMCS_ATTR(HOST_SS_SELECTOR, u16);
VMCS_ATTR(HOST_DS_SELECTOR, u16);
VMCS_ATTR(HOST_FS_SELECTOR, u16);
VMCS_ATTR(HOST_GS_SELECTOR, u16);
VMCS_ATTR(HOST_TR_SELECTOR, u16);
VMCS_ATTR(IO_BITMAP_A, u64);
VMCS_ATTR(IO_BITMAP_A_HIGH, u64);
VMCS_ATTR(IO_BITMAP_B, u64);
VMCS_ATTR(IO_BITMAP_B_HIGH, u64);
VMCS_ATTR(MSR_BITMAP, u64);
VMCS_ATTR(MSR_BITMAP_HIGH, u64);
VMCS_ATTR(VM_EXIT_MSR_STORE_ADDR, u64);
VMCS_ATTR(VM_EXIT_MSR_STORE_ADDR_HIGH, u64);
VMCS_ATTR(VM_EXIT_MSR_LOAD_ADDR, u64);
VMCS_ATTR(VM_EXIT_MSR_LOAD_ADDR_HIGH, u64);
VMCS_ATTR(VM_ENTRY_MSR_LOAD_ADDR, u64);
VMCS_ATTR(VM_ENTRY_MSR_LOAD_ADDR_HIGH, u64);
VMCS_ATTR(PML_ADDRESS, u64);
VMCS_ATTR(PML_ADDRESS_HIGH, u64);
VMCS_ATTR(TSC_OFFSET, u64);
VMCS_ATTR(TSC_OFFSET_HIGH, u64);
VMCS_ATTR(VIRTUAL_APIC_PAGE_ADDR, u64);
VMCS_ATTR(VIRTUAL_APIC_PAGE_ADDR_HIGH, u64);
VMCS_ATTR(APIC_ACCESS_ADDR, u64);
VMCS_ATTR(APIC_ACCESS_ADDR_HIGH, u64);
VMCS_ATTR(POSTED_INTR_DESC_ADDR, u64);
VMCS_ATTR(POSTED_INTR_DESC_ADDR_HIGH, u64);
VMCS_ATTR(EPT_POINTER, u64);
VMCS_ATTR(EPT_POINTER_HIGH, u64);
VMCS_ATTR(EOI_EXIT_BITMAP0, u64);
VMCS_ATTR(EOI_EXIT_BITMAP0_HIGH, u64);
VMCS_ATTR(EOI_EXIT_BITMAP1, u64);
VMCS_ATTR(EOI_EXIT_BITMAP1_HIGH, u64);
VMCS_ATTR(EOI_EXIT_BITMAP2, u64);
VMCS_ATTR(EOI_EXIT_BITMAP2_HIGH, u64);
VMCS_ATTR(EOI_EXIT_BITMAP3, u64);
VMCS_ATTR(EOI_EXIT_BITMAP3_HIGH, u64);
VMCS_ATTR(VMREAD_BITMAP, u64);
VMCS_ATTR(VMWRITE_BITMAP, u64);
VMCS_ATTR(XSS_EXIT_BITMAP, u64);
VMCS_ATTR(XSS_EXIT_BITMAP_HIGH, u64);
VMCS_ATTR(TSC_MULTIPLIER, u64);
VMCS_ATTR(TSC_MULTIPLIER_HIGH, u64);
VMCS_ATTR_RO(GUEST_PHYSICAL_ADDRESS, u64);
VMCS_ATTR_RO(GUEST_PHYSICAL_ADDRESS_HIGH, u64);
VMCS_ATTR(VMCS_LINK_POINTER, u64);
VMCS_ATTR(VMCS_LINK_POINTER_HIGH, u64);
VMCS_ATTR(GUEST_IA32_DEBUGCTL, u64);
VMCS_ATTR(GUEST_IA32_DEBUGCTL_HIGH, u64);
VMCS_ATTR(GUEST_IA32_PAT, u64);
VMCS_ATTR(GUEST_IA32_PAT_HIGH, u64);
VMCS_ATTR(GUEST_IA32_EFER, u64);
VMCS_ATTR(GUEST_IA32_EFER_HIGH, u64);
VMCS_ATTR(GUEST_IA32_PERF_GLOBAL_CTRL, u64);
VMCS_ATTR(GUEST_IA32_PERF_GLOBAL_CTRL_HIGH, u64);
VMCS_ATTR(GUEST_PDPTR0, u64);
VMCS_ATTR(GUEST_PDPTR0_HIGH, u64);
VMCS_ATTR(GUEST_PDPTR1, u64);
VMCS_ATTR(GUEST_PDPTR1_HIGH, u64);
VMCS_ATTR(GUEST_PDPTR2, u64);
VMCS_ATTR(GUEST_PDPTR2_HIGH, u64);
VMCS_ATTR(GUEST_PDPTR3, u64);
VMCS_ATTR(GUEST_PDPTR3_HIGH, u64);
VMCS_ATTR(GUEST_BNDCFGS, u64);
VMCS_ATTR(GUEST_BNDCFGS_HIGH, u64);
VMCS_ATTR(HOST_IA32_PAT, u64);
VMCS_ATTR(HOST_IA32_PAT_HIGH, u64);
VMCS_ATTR(HOST_IA32_EFER, u64);
VMCS_ATTR(HOST_IA32_EFER_HIGH, u64);
VMCS_ATTR(HOST_IA32_PERF_GLOBAL_CTRL, u64);
VMCS_ATTR(HOST_IA32_PERF_GLOBAL_CTRL_HIGH, u64);
VMCS_ATTR(PIN_BASED_VM_EXEC_CONTROL, u32);
VMCS_ATTR(CPU_BASED_VM_EXEC_CONTROL, u32);
VMCS_ATTR(EXCEPTION_BITMAP, u32);
VMCS_ATTR(PAGE_FAULT_ERROR_CODE_MASK, u32);
VMCS_ATTR(PAGE_FAULT_ERROR_CODE_MATCH, u32);
VMCS_ATTR(CR3_TARGET_COUNT, u32);
VMCS_ATTR(VM_EXIT_CONTROLS, u32);
VMCS_ATTR(VM_EXIT_MSR_STORE_COUNT, u32);
VMCS_ATTR(VM_EXIT_MSR_LOAD_COUNT, u32);
VMCS_ATTR(VM_ENTRY_CONTROLS, u32);
VMCS_ATTR(VM_ENTRY_MSR_LOAD_COUNT, u32);
VMCS_ATTR(VM_ENTRY_INTR_INFO_FIELD, u32);
VMCS_ATTR(VM_ENTRY_EXCEPTION_ERROR_CODE, u32);
VMCS_ATTR(VM_ENTRY_INSTRUCTION_LEN, u32);
VMCS_ATTR(TPR_THRESHOLD, u32);
VMCS_ATTR(SECONDARY_VM_EXEC_CONTROL, u32);
VMCS_ATTR(PLE_GAP, u32);
VMCS_ATTR(PLE_WINDOW, u32);
VMCS_ATTR_RO(VM_INSTRUCTION_ERROR, u32);
VMCS_ATTR_RO(VM_EXIT_REASON, u32);
VMCS_ATTR_RO(VM_EXIT_INTR_INFO, u32);
VMCS_ATTR_RO(VM_EXIT_INTR_ERROR_CODE, u32);
VMCS_ATTR_RO(IDT_VECTORING_INFO_FIELD, u32);
VMCS_ATTR_RO(IDT_VECTORING_ERROR_CODE, u32);
VMCS_ATTR_RO(VM_EXIT_INSTRUCTION_LEN, u32);
VMCS_ATTR_RO(VMX_INSTRUCTION_INFO, u32);
VMCS_ATTR(GUEST_ES_LIMIT, u32);
VMCS_ATTR(GUEST_CS_LIMIT, u32);
VMCS_ATTR(GUEST_SS_LIMIT, u32);
VMCS_ATTR(GUEST_DS_LIMIT, u32);
VMCS_ATTR(GUEST_FS_LIMIT, u32);
VMCS_ATTR(GUEST_GS_LIMIT, u32);
VMCS_ATTR(GUEST_LDTR_LIMIT, u32);
VMCS_ATTR(GUEST_TR_LIMIT, u32);
VMCS_ATTR(GUEST_GDTR_LIMIT, u32);
VMCS_ATTR(GUEST_IDTR_LIMIT, u32);
VMCS_ATTR(GUEST_ES_AR_BYTES, u32);
VMCS_ATTR(GUEST_CS_AR_BYTES, u32);
VMCS_ATTR(GUEST_SS_AR_BYTES, u32);
VMCS_ATTR(GUEST_DS_AR_BYTES, u32);
VMCS_ATTR(GUEST_FS_AR_BYTES, u32);
VMCS_ATTR(GUEST_GS_AR_BYTES, u32);
VMCS_ATTR(GUEST_LDTR_AR_BYTES, u32);
VMCS_ATTR(GUEST_TR_AR_BYTES, u32);
VMCS_ATTR(GUEST_INTERRUPTIBILITY_INFO, u32);
VMCS_ATTR(GUEST_ACTIVITY_STATE, u32);
VMCS_ATTR(GUEST_SYSENTER_CS, u32);
VMCS_ATTR(VMX_PREEMPTION_TIMER_VALUE, u32);
VMCS_ATTR(HOST_IA32_SYSENTER_CS, u32);
VMCS_ATTR(CR0_GUEST_HOST_MASK, natural_width);
VMCS_ATTR(CR4_GUEST_HOST_MASK, natural_width);
VMCS_ATTR(CR0_READ_SHADOW, natural_width);
VMCS_ATTR(CR4_READ_SHADOW, natural_width);
VMCS_ATTR(CR3_TARGET_VALUE0, natural_width);
VMCS_ATTR(CR3_TARGET_VALUE1, natural_width);
VMCS_ATTR(CR3_TARGET_VALUE2, natural_width);
VMCS_ATTR(CR3_TARGET_VALUE3, natural_width);
VMCS_ATTR_RO(EXIT_QUALIFICATION, natural_width);
VMCS_ATTR_RO(GUEST_LINEAR_ADDRESS, natural_width);
VMCS_ATTR(GUEST_CR0, natural_width);
VMCS_ATTR(GUEST_CR3, natural_width);
VMCS_ATTR(GUEST_CR4, natural_width);
VMCS_ATTR(GUEST_ES_BASE, natural_width);
VMCS_ATTR(GUEST_CS_BASE, natural_width);
VMCS_ATTR(GUEST_SS_BASE, natural_width);
VMCS_ATTR(GUEST_DS_BASE, natural_width);
VMCS_ATTR(GUEST_FS_BASE, natural_width);
VMCS_ATTR(GUEST_GS_BASE, natural_width);
VMCS_ATTR(GUEST_LDTR_BASE, natural_width);
VMCS_ATTR(GUEST_TR_BASE, natural_width);
VMCS_ATTR(GUEST_GDTR_BASE, natural_width);
VMCS_ATTR(GUEST_IDTR_BASE, natural_width);
VMCS_ATTR(GUEST_DR7, natural_width);
VMCS_ATTR(GUEST_RSP, natural_width);
VMCS_ATTR(GUEST_RIP, natural_width);
VMCS_ATTR(GUEST_RFLAGS, natural_width);
VMCS_ATTR(GUEST_PENDING_DBG_EXCEPTIONS, natural_width);
VMCS_ATTR(GUEST_SYSENTER_ESP, natural_width);
VMCS_ATTR(GUEST_SYSENTER_EIP, natural_width);
VMCS_ATTR(HOST_CR0, natural_width);
VMCS_ATTR(HOST_CR3, natural_width);
VMCS_ATTR(HOST_CR4, natural_width);
VMCS_ATTR(HOST_FS_BASE, natural_width);
VMCS_ATTR(HOST_GS_BASE, natural_width);
VMCS_ATTR(HOST_TR_BASE, natural_width);
VMCS_ATTR(HOST_GDTR_BASE, natural_width);
VMCS_ATTR(HOST_IDTR_BASE, natural_width);
VMCS_ATTR(HOST_IA32_SYSENTER_ESP, natural_width);
VMCS_ATTR(HOST_IA32_SYSENTER_EIP, natural_width);
VMCS_ATTR(HOST_RSP, natural_width);
VMCS_ATTR(HOST_RIP, natural_width);

static struct kobj_attribute revision_id_attribute =
	__ATTR(revision_id, 0444, revision_id_show, NULL);

static struct kobj_attribute abort_attribute =
	__ATTR(abort, 0444, abort_show, NULL);

static struct attribute *vmcsctl_attrs[] = {
	&revision_id_attribute.attr,
	&abort_attribute.attr,
	&vmcs_field_VIRTUAL_PROCESSOR_ID.attr,
	&vmcs_field_POSTED_INTR_NV.attr,
	&vmcs_field_GUEST_ES_SELECTOR.attr,
	&vmcs_field_GUEST_CS_SELECTOR.attr,
	&vmcs_field_GUEST_SS_SELECTOR.attr,
	&vmcs_field_GUEST_DS_SELECTOR.attr,
	&vmcs_field_GUEST_FS_SELECTOR.attr,
	&vmcs_field_GUEST_GS_SELECTOR.attr,
	&vmcs_field_GUEST_LDTR_SELECTOR.attr,
	&vmcs_field_GUEST_TR_SELECTOR.attr,
	&vmcs_field_GUEST_INTR_STATUS.attr,
	&vmcs_field_GUEST_PML_INDEX.attr,
	&vmcs_field_HOST_ES_SELECTOR.attr,
	&vmcs_field_HOST_CS_SELECTOR.attr,
	&vmcs_field_HOST_SS_SELECTOR.attr,
	&vmcs_field_HOST_DS_SELECTOR.attr,
	&vmcs_field_HOST_FS_SELECTOR.attr,
	&vmcs_field_HOST_GS_SELECTOR.attr,
	&vmcs_field_HOST_TR_SELECTOR.attr,
	&vmcs_field_IO_BITMAP_A.attr,
	&vmcs_field_IO_BITMAP_A_HIGH.attr,
	&vmcs_field_IO_BITMAP_B.attr,
	&vmcs_field_IO_BITMAP_B_HIGH.attr,
	&vmcs_field_MSR_BITMAP.attr,
	&vmcs_field_MSR_BITMAP_HIGH.attr,
	&vmcs_field_VM_EXIT_MSR_STORE_ADDR.attr,
	&vmcs_field_VM_EXIT_MSR_STORE_ADDR_HIGH.attr,
	&vmcs_field_VM_EXIT_MSR_LOAD_ADDR.attr,
	&vmcs_field_VM_EXIT_MSR_LOAD_ADDR_HIGH.attr,
	&vmcs_field_VM_ENTRY_MSR_LOAD_ADDR.attr,
	&vmcs_field_VM_ENTRY_MSR_LOAD_ADDR_HIGH.attr,
	&vmcs_field_PML_ADDRESS.attr,
	&vmcs_field_PML_ADDRESS_HIGH.attr,
	&vmcs_field_TSC_OFFSET.attr,
	&vmcs_field_TSC_OFFSET_HIGH.attr,
	&vmcs_field_VIRTUAL_APIC_PAGE_ADDR.attr,
	&vmcs_field_VIRTUAL_APIC_PAGE_ADDR_HIGH.attr,
	&vmcs_field_APIC_ACCESS_ADDR.attr,
	&vmcs_field_APIC_ACCESS_ADDR_HIGH.attr,
	&vmcs_field_POSTED_INTR_DESC_ADDR.attr,
	&vmcs_field_POSTED_INTR_DESC_ADDR_HIGH.attr,
	&vmcs_field_EPT_POINTER.attr,
	&vmcs_field_EPT_POINTER_HIGH.attr,
	&vmcs_field_EOI_EXIT_BITMAP0.attr,
	&vmcs_field_EOI_EXIT_BITMAP0_HIGH.attr,
	&vmcs_field_EOI_EXIT_BITMAP1.attr,
	&vmcs_field_EOI_EXIT_BITMAP1_HIGH.attr,
	&vmcs_field_EOI_EXIT_BITMAP2.attr,
	&vmcs_field_EOI_EXIT_BITMAP2_HIGH.attr,
	&vmcs_field_EOI_EXIT_BITMAP3.attr,
	&vmcs_field_EOI_EXIT_BITMAP3_HIGH.attr,
	&vmcs_field_VMREAD_BITMAP.attr,
	&vmcs_field_VMWRITE_BITMAP.attr,
	&vmcs_field_XSS_EXIT_BITMAP.attr,
	&vmcs_field_XSS_EXIT_BITMAP_HIGH.attr,
	&vmcs_field_TSC_MULTIPLIER.attr,
	&vmcs_field_TSC_MULTIPLIER_HIGH.attr,
	&vmcs_field_GUEST_PHYSICAL_ADDRESS.attr,
	&vmcs_field_GUEST_PHYSICAL_ADDRESS_HIGH.attr,
	&vmcs_field_VMCS_LINK_POINTER.attr,
	&vmcs_field_VMCS_LINK_POINTER_HIGH.attr,
	&vmcs_field_GUEST_IA32_DEBUGCTL.attr,
	&vmcs_field_GUEST_IA32_DEBUGCTL_HIGH.attr,
	&vmcs_field_GUEST_IA32_PAT.attr,
	&vmcs_field_GUEST_IA32_PAT_HIGH.attr,
	&vmcs_field_GUEST_IA32_EFER.attr,
	&vmcs_field_GUEST_IA32_EFER_HIGH.attr,
	&vmcs_field_GUEST_IA32_PERF_GLOBAL_CTRL.attr,
	&vmcs_field_GUEST_IA32_PERF_GLOBAL_CTRL_HIGH.attr,
	&vmcs_field_GUEST_PDPTR0.attr,
	&vmcs_field_GUEST_PDPTR0_HIGH.attr,
	&vmcs_field_GUEST_PDPTR1.attr,
	&vmcs_field_GUEST_PDPTR1_HIGH.attr,
	&vmcs_field_GUEST_PDPTR2.attr,
	&vmcs_field_GUEST_PDPTR2_HIGH.attr,
	&vmcs_field_GUEST_PDPTR3.attr,
	&vmcs_field_GUEST_PDPTR3_HIGH.attr,
	&vmcs_field_GUEST_BNDCFGS.attr,
	&vmcs_field_GUEST_BNDCFGS_HIGH.attr,
	&vmcs_field_HOST_IA32_PAT.attr,
	&vmcs_field_HOST_IA32_PAT_HIGH.attr,
	&vmcs_field_HOST_IA32_EFER.attr,
	&vmcs_field_HOST_IA32_EFER_HIGH.attr,
	&vmcs_field_HOST_IA32_PERF_GLOBAL_CTRL.attr,
	&vmcs_field_HOST_IA32_PERF_GLOBAL_CTRL_HIGH.attr,
	&vmcs_field_PIN_BASED_VM_EXEC_CONTROL.attr,
	&vmcs_field_CPU_BASED_VM_EXEC_CONTROL.attr,
	&vmcs_field_EXCEPTION_BITMAP.attr,
	&vmcs_field_PAGE_FAULT_ERROR_CODE_MASK.attr,
	&vmcs_field_PAGE_FAULT_ERROR_CODE_MATCH.attr,
	&vmcs_field_CR3_TARGET_COUNT.attr,
	&vmcs_field_VM_EXIT_CONTROLS.attr,
	&vmcs_field_VM_EXIT_MSR_STORE_COUNT.attr,
	&vmcs_field_VM_EXIT_MSR_LOAD_COUNT.attr,
	&vmcs_field_VM_ENTRY_CONTROLS.attr,
	&vmcs_field_VM_ENTRY_MSR_LOAD_COUNT.attr,
	&vmcs_field_VM_ENTRY_INTR_INFO_FIELD.attr,
	&vmcs_field_VM_ENTRY_EXCEPTION_ERROR_CODE.attr,
	&vmcs_field_VM_ENTRY_INSTRUCTION_LEN.attr,
	&vmcs_field_TPR_THRESHOLD.attr,
	&vmcs_field_SECONDARY_VM_EXEC_CONTROL.attr,
	&vmcs_field_PLE_GAP.attr,
	&vmcs_field_PLE_WINDOW.attr,
	&vmcs_field_VM_INSTRUCTION_ERROR.attr,
	&vmcs_field_VM_EXIT_REASON.attr,
	&vmcs_field_VM_EXIT_INTR_INFO.attr,
	&vmcs_field_VM_EXIT_INTR_ERROR_CODE.attr,
	&vmcs_field_IDT_VECTORING_INFO_FIELD.attr,
	&vmcs_field_IDT_VECTORING_ERROR_CODE.attr,
	&vmcs_field_VM_EXIT_INSTRUCTION_LEN.attr,
	&vmcs_field_VMX_INSTRUCTION_INFO.attr,
	&vmcs_field_GUEST_ES_LIMIT.attr,
	&vmcs_field_GUEST_CS_LIMIT.attr,
	&vmcs_field_GUEST_SS_LIMIT.attr,
	&vmcs_field_GUEST_DS_LIMIT.attr,
	&vmcs_field_GUEST_FS_LIMIT.attr,
	&vmcs_field_GUEST_GS_LIMIT.attr,
	&vmcs_field_GUEST_LDTR_LIMIT.attr,
	&vmcs_field_GUEST_TR_LIMIT.attr,
	&vmcs_field_GUEST_GDTR_LIMIT.attr,
	&vmcs_field_GUEST_IDTR_LIMIT.attr,
	&vmcs_field_GUEST_ES_AR_BYTES.attr,
	&vmcs_field_GUEST_CS_AR_BYTES.attr,
	&vmcs_field_GUEST_SS_AR_BYTES.attr,
	&vmcs_field_GUEST_DS_AR_BYTES.attr,
	&vmcs_field_GUEST_FS_AR_BYTES.attr,
	&vmcs_field_GUEST_GS_AR_BYTES.attr,
	&vmcs_field_GUEST_LDTR_AR_BYTES.attr,
	&vmcs_field_GUEST_TR_AR_BYTES.attr,
	&vmcs_field_GUEST_INTERRUPTIBILITY_INFO.attr,
	&vmcs_field_GUEST_ACTIVITY_STATE.attr,
	&vmcs_field_GUEST_SYSENTER_CS.attr,
	&vmcs_field_VMX_PREEMPTION_TIMER_VALUE.attr,
	&vmcs_field_HOST_IA32_SYSENTER_CS.attr,
	&vmcs_field_CR0_GUEST_HOST_MASK.attr,
	&vmcs_field_CR4_GUEST_HOST_MASK.attr,
	&vmcs_field_CR0_READ_SHADOW.attr,
	&vmcs_field_CR4_READ_SHADOW.attr,
	&vmcs_field_CR3_TARGET_VALUE0.attr,
	&vmcs_field_CR3_TARGET_VALUE1.attr,
	&vmcs_field_CR3_TARGET_VALUE2.attr,
	&vmcs_field_CR3_TARGET_VALUE3.attr,
	&vmcs_field_EXIT_QUALIFICATION.attr,
	&vmcs_field_GUEST_LINEAR_ADDRESS.attr,
	&vmcs_field_GUEST_CR0.attr,
	&vmcs_field_GUEST_CR3.attr,
	&vmcs_field_GUEST_CR4.attr,
	&vmcs_field_GUEST_ES_BASE.attr,
	&vmcs_field_GUEST_CS_BASE.attr,
	&vmcs_field_GUEST_SS_BASE.attr,
	&vmcs_field_GUEST_DS_BASE.attr,
	&vmcs_field_GUEST_FS_BASE.attr,
	&vmcs_field_GUEST_GS_BASE.attr,
	&vmcs_field_GUEST_LDTR_BASE.attr,
	&vmcs_field_GUEST_TR_BASE.attr,
	&vmcs_field_GUEST_GDTR_BASE.attr,
	&vmcs_field_GUEST_IDTR_BASE.attr,
	&vmcs_field_GUEST_DR7.attr,
	&vmcs_field_GUEST_RSP.attr,
	&vmcs_field_GUEST_RIP.attr,
	&vmcs_field_GUEST_RFLAGS.attr,
	&vmcs_field_GUEST_PENDING_DBG_EXCEPTIONS.attr,
	&vmcs_field_GUEST_SYSENTER_ESP.attr,
	&vmcs_field_GUEST_SYSENTER_EIP.attr,
	&vmcs_field_HOST_CR0.attr,
	&vmcs_field_HOST_CR3.attr,
	&vmcs_field_HOST_CR4.attr,
	&vmcs_field_HOST_FS_BASE.attr,
	&vmcs_field_HOST_GS_BASE.attr,
	&vmcs_field_HOST_TR_BASE.attr,
	&vmcs_field_HOST_GDTR_BASE.attr,
	&vmcs_field_HOST_IDTR_BASE.attr,
	&vmcs_field_HOST_IA32_SYSENTER_ESP.attr,
	&vmcs_field_HOST_IA32_SYSENTER_EIP.attr,
	&vmcs_field_HOST_RSP.attr,
	&vmcs_field_HOST_RIP.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static struct attribute_group attr_group = {
	.attrs = vmcsctl_attrs,
};

static struct vmcsctl *vmcsctl_create(struct vmcs *vmcs)
{
	struct vmcsctl *new;

	new = kzalloc(sizeof(*new), GFP_KERNEL);
	if (new == NULL)
		return NULL;
	kobject_init(&new->kobj, &vmcsctl_kobj_ktype);
	new->vmcs = vmcs;
	new->pid = task_pid_nr(current);
	return new;
}

static void vmcsctl_del(struct vmcsctl *vmcsctl)
{
	kobject_del(&vmcsctl->kobj);
	kfree(vmcsctl);
}

int vmcsctl_register(struct vmcs *vmcs)
{
	int err;
	struct vmcsctl *vmcsctl;

	WARN_ON(vmcs == NULL);
	vmcsctl = vmcsctl_create(vmcs);
	if (vmcsctl == NULL)
		return -1;
	vmcsctl->kobj.kset = vmcsctl_set;
	err = kobject_add(&vmcsctl->kobj, NULL, "vmcs%d",
			vmcsctl->pid);
	if (err != 0)
		goto out;
	err = sysfs_create_group(&vmcsctl->kobj, &attr_group);
	if (err != 0)
		goto out;
	return 0;
out:
	vmcsctl_del(vmcsctl);
	return err;
}

void vmcsctl_unregister(struct vmcs *vmcs)
{
	struct kobject *kobj;
	struct vmcsctl *vmcsctl;

	list_for_each_entry(kobj, &vmcsctl_set->list, entry) {
		vmcsctl = vmcsctl_container_of(kobj);
		if (vmcsctl->vmcs == vmcs) {
			vmcsctl_del(vmcsctl);
			return;
		}
	}
}

void vmcsctl_vmxon(void)
{
	vmxon = true;
}

void vmcsctl_vmxoff(void)
{
	vmxon = false;
}

static int __init vmcsctl_init(void)
{
	int err;

	vmcsctl_set = kset_create_and_add("vmcsctl", NULL, kernel_kobj);
	if (vmcsctl_set == NULL)
		return -ENOMEM;
	err = kset_register(vmcsctl_set);
	if (err != 0)
		return err;
	return 0;
}

static void __exit vmcsctl_exit(void)
{
	kset_unregister(vmcsctl_set);
	kset_put(vmcsctl_set);
}

module_init(vmcsctl_init);
module_exit(vmcsctl_exit);

MODULE_AUTHOR("Ian Kronquist <iankronquist@gmail.com>");
MODULE_LICENSE("Dual MIT/GPL");
