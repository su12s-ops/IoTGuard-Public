/* SPDX-License-Identifier: Apache-2.0
 * Trusted QEMU guest only: this transport grants the guest semihosting access
 * to host files. It is not a physical-device entropy implementation.
 */
#define DT_DRV_COMPAT iotguard_qemu_host_entropy
#include <errno.h>
#include <string.h>
#include <zephyr/arch/common/semihost.h>
#include <zephyr/device.h>
#include <zephyr/drivers/entropy.h>
#include <zephyr/kernel.h>

static int host_get_entropy(const struct device *dev, uint8_t *buf, uint16_t len)
{
	ARG_UNUSED(dev);
	long fd = semihost_open("/dev/urandom", SEMIHOST_OPEN_RB);
	if (fd < 0) {
		memset(buf, 0, len);
		return -EIO;
	}
	long received = semihost_read(fd, buf, len);
	long closed = semihost_close(fd);
	if (received != len || closed != 0) {
		memset(buf, 0, len);
		return -EIO;
	}
	return 0;
}

static int host_entropy_init(const struct device *dev)
{
	uint8_t probe[32];
	int rc = host_get_entropy(dev, probe, sizeof(probe));
	memset(probe, 0, sizeof(probe));
	return rc;
}

static DEVICE_API(entropy, host_entropy_api) = {
	.get_entropy = host_get_entropy,
};
DEVICE_DT_INST_DEFINE(0, host_entropy_init, NULL, NULL, NULL, PRE_KERNEL_1,
		      CONFIG_ENTROPY_INIT_PRIORITY, &host_entropy_api);
