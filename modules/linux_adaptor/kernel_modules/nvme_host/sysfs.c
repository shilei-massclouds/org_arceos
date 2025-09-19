#include <linux/nvme-auth.h>

#include "nvme.h"
#include "fabrics.h"
#include "../adaptor.h"

static struct attribute *nvme_ns_attrs[] = {
#if 0
    &dev_attr_wwid.attr,
    &dev_attr_uuid.attr,
    &dev_attr_nguid.attr,
    &dev_attr_eui.attr,
    &dev_attr_csi.attr,
    &dev_attr_nsid.attr,
    &dev_attr_metadata_bytes.attr,
    &dev_attr_nuse.attr,
#ifdef CONFIG_NVME_MULTIPATH
    &dev_attr_ana_grpid.attr,
    &dev_attr_ana_state.attr,
#endif
    &dev_attr_io_passthru_err_log_enabled.attr,
#endif
    NULL,
};

static umode_t nvme_ns_attrs_are_visible(struct kobject *kobj,
        struct attribute *a, int n)
{
    PANIC("");
}

const struct attribute_group *nvme_dev_attr_groups[] = {
    &nvme_dev_attrs_group,
#ifdef CONFIG_NVME_TCP_TLS
    &nvme_tls_attrs_group,
#endif
    NULL,
};

static const struct attribute_group nvme_ns_attr_group = {
    .attrs      = nvme_ns_attrs,
    .is_visible = nvme_ns_attrs_are_visible,
};

const struct attribute_group *nvme_ns_attr_groups[] = {
    &nvme_ns_attr_group,
    NULL,
};
