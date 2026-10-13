/* 诊断版：无网络依赖，纯 printk + 循环。用于隔离启动问题。 */
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

int main(void)
{
	printk("=== SENSOR-01 DIAGNOSTIC BOOT OK ===\n");
	printk("board=%s\n", CONFIG_BOARD);
	for (;;) {
		k_sleep(K_SECONDS(1));
	}
	return 0;
}
