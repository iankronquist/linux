#ifndef __VMCSCTL_H
#define __VMCSCTL_H

#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/sysfs.h>

#include <asm/vmx.h>

struct vmcs;

struct vmcsctl {
	int pid;
	struct kobject kobj;
	struct vmcs *vmcs;
};

int vmcsctl_register(struct vmcs *vmcs);

void vmcsctl_unregister(struct vmcs *vmcs);

void vmcsctl_vmxon(void);

void vmcsctl_vmxoff(void);
#endif
