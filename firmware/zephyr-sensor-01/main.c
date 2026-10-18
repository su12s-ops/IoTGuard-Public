/*
 * Zephyr-Sensor-01 — IoTGuard 第七阶段虚拟环境监测终端（Zephyr RTOS v4.4.2 真实固件）
 *
 * 真实 Zephyr 应用：TCP 服务线程 + 模拟传感线程 + DHCP 网络初始化。
 * 身份与固件信息全部来自编译配置与运行时状态（内核版本/board/MAC/构建时间），
 * 遥测标记 simulated，不冒充实物采样；只读接口，无任何控制端点。
 * 板级目标：qemu_cortex_a9（系统 qemu-system-arm xilinx-zynq-a9 + SLIRP hostfwd
 * 提供入站可达性；x86_64 路径因 e1000 驱动崩溃已弃用，见 IOT_STAGE7_ZEPHYR_REPORT.md）。
 */
#include <zephyr/kernel.h>
#include <zephyr/kernel_version.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_event.h>
#include <zephyr/sys/printk.h>
#include <zephyr/random/random.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define APP_PORT       CONFIG_APP_HTTP_PORT
#define RX_BUF_SIZE    256
#define TX_BUF_SIZE    1024
#define SERVER_STACK   6144
#define SENSOR_STACK   2048

/* 架构如实上报（编译期判定，不硬编码）：ARM 构建报 arm，x86_64 构建报 x86_64 */
#if defined(CONFIG_ARM)
#define APP_ARCH "arm"
#elif defined(CONFIG_X86_64)
#define APP_ARCH "x86_64"
#else
#define APP_ARCH "unknown"
#endif

static const char HDR_JSON[] =
	"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n";
static const char HDR_HTML[] =
	"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n";

/* 模拟传感数据（标记 simulated，见 /api/system 响应）；多线程访问用原子量 */
static atomic_t temperature_cx10 = 251;  /* 25.1 ℃ */
static atomic_t humidity_x10     = 572;  /* 57.2 % */

static K_THREAD_STACK_DEFINE(server_stack, SERVER_STACK);
static K_THREAD_STACK_DEFINE(sensor_stack, SENSOR_STACK);
static struct k_thread server_thread;
static struct k_thread sensor_thread;

/* 有界追加构建器：全部写入经 bound 检查，绝不出界 */
struct builder {
	char *buf;
	size_t cap;
	size_t len;
};

static void b_reset(struct builder *b, char *buf, size_t cap)
{
	b->buf = buf;
	b->cap = cap;
	b->len = 0;
	if (cap > 0) {
		buf[0] = '\0';
	}
}

static void b_lit(struct builder *b, const char *s)
{
	size_t n;
	if (b->len + 1 >= b->cap) {
		return;
	}
	n = strlen(s);
	if (n > b->cap - b->len - 1) {
		n = b->cap - b->len - 1;
	}
	memcpy(b->buf + b->len, s, n);
	b->len += n;
	b->buf[b->len] = '\0';
}

static void b_field(struct builder *b, const char *name, const char *value)
{
	b_lit(b, "\"");
	b_lit(b, name);
	b_lit(b, "\":\"");
	b_lit(b, value);
	b_lit(b, "\",");
}

static void b_num(struct builder *b, const char *name, uint32_t value, bool comma)
{
	char num[16];
	snprintf(num, sizeof(num), "%lu", (unsigned long)value);
	b_lit(b, "\"");
	b_lit(b, name);
	b_lit(b, "\":");
	b_lit(b, num);
	b_lit(b, comma ? "," : "");
}

static void sensor_sim_loop(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1); ARG_UNUSED(p2); ARG_UNUSED(p3);
	int8_t drift = 1;
	for (;;) {
		k_sleep(K_SECONDS(CONFIG_APP_SENSOR_INTERVAL_S));
		int t = atomic_get(&temperature_cx10) + drift;
		int h = atomic_get(&humidity_x10) - (drift / 2);
		if (t > 299 || t < 200) {
			drift = (int8_t)-drift;
		}
		atomic_set(&temperature_cx10, t);
		atomic_set(&humidity_x10, h);
	}
}

static void read_mac(char *out, size_t out_len)
{
	const uint8_t *addr = NULL;
	static const uint8_t zero_mac[6] = { 0 };
	struct net_if *iface = net_if_get_default();

	if (iface != NULL) {
		addr = net_if_get_link_addr(iface)->addr;
	}
	if (addr == NULL) {
		addr = zero_mac;
	}
	size_t used = 0;
	for (int i = 0; i < 6; i++) {
		used += (size_t)snprintf(out + used, out_len - used, "%s%02x",
					 i ? ":" : "", addr[i]);
		if (used >= out_len - 1) {
			break;
		}
	}
	out[out_len - 1] = '\0';
}

static void read_os(char *out, size_t out_len)
{
	uint32_t ver = sys_kernel_version_get();
	snprintf(out, out_len, "Zephyr RTOS %d.%d.%d",
		 SYS_KERNEL_VER_MAJOR(ver),
		 SYS_KERNEL_VER_MINOR(ver),
		 SYS_KERNEL_VER_PATCHLEVEL(ver));
}

static int send_all(int fd, const char *buf, size_t len)
{
	size_t off = 0;
	while (off < len) {
		ssize_t n = zsock_send(fd, buf + off, len - off, 0);
		if (n <= 0) {
			return -1;
		}
		off += (size_t)n;
	}
	return 0;
}

static void build_identity_json(struct builder *b)
{
	char mac[24], os[48], ver[16];
	int t = atomic_get(&temperature_cx10);
	int h = atomic_get(&humidity_x10);

	read_mac(mac, sizeof(mac));
	read_os(os, sizeof(os));
	b_lit(b, "{");
	b_field(b, "device_name", CONFIG_APP_DEVICE_NAME);
	b_field(b, "device_type", "zephyr_sensor");
	b_field(b, "vendor", CONFIG_APP_VENDOR);
	b_field(b, "model", CONFIG_APP_MODEL);
	b_field(b, "firmware_version", CONFIG_APP_FW_VERSION);
	b_field(b, "os", os);
	b_field(b, "device_id", CONFIG_APP_DEVICE_UID);
	b_field(b, "board", CONFIG_BOARD);
	b_field(b, "arch", APP_ARCH);
	b_field(b, "build_id", __DATE__ " " __TIME__);
	b_field(b, "status", "online");
	if (IS_ENABLED(CONFIG_APP_QEMU_HOST_ENTROPY)) {
		b_field(b, "entropy_source", "qemu_host_urandom_semihost");
		b_field(b, "entropy_self_test", "passed");
	}
	b_field(b, "mac_address", mac);
	snprintf(ver, sizeof(ver), "%d.%d", t / 10, ((t < 0) ? -t : t) % 10);
	b_lit(b, "\"telemetry\":{\"temperature_c\":{\"value\":");
	b_lit(b, ver);
	b_lit(b, ",\"simulated\":true},");
	snprintf(ver, sizeof(ver), "%d.%d", h / 10, ((h < 0) ? -h : h) % 10);
	b_lit(b, "\"humidity_pct\":{\"value\":");
	b_lit(b, ver);
	b_lit(b, ",\"simulated\":true}},");
	b_lit(b, "\"services\":[{\"type\":\"http\",");
	b_num(b, "port", (uint32_t)APP_PORT, false);
	b->buf[b->len] = '\0';
	b_lit(b, ",\"product\":\"zephyr-sensor-httpd ");
	b_lit(b, CONFIG_APP_FW_VERSION);
	b_lit(b, "\"}]}\n");
}

static void handle_client(int fd)
{
	char rx[RX_BUF_SIZE];
	char body[TX_BUF_SIZE];
	struct builder b;
	struct zsock_timeval timeout = { .tv_sec = 2, .tv_usec = 0 };
	if (zsock_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
	    zsock_setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
		zsock_close(fd);
		return;
	}

	/* A total deadline also bounds clients which trickle a byte at a time. */
	size_t used = 0;
	int64_t deadline = k_uptime_get() + 2000;
	bool complete = false;
	while (used < sizeof(rx) - 1 && k_uptime_get() < deadline) {
		ssize_t n = zsock_recv(fd, rx + used, sizeof(rx) - used - 1, 0);
		if (n <= 0) {
			break;
		}
		used += (size_t)n;
		rx[used] = '\0';
		if (strstr(rx, "\r\n") != NULL) {
			complete = true;
			break;
		}
	}
	if (!complete) {
		zsock_close(fd);
		return;
	}
	char method[8], path[128], protocol[16], extra;
	char *line_end = strstr(rx, "\r\n");
	*line_end = '\0';
	if (sscanf(rx, "%7s %127s %15s %c", method, path, protocol, &extra) != 3 ||
	    strcmp(method, "GET") != 0 ||
	    (strcmp(protocol, "HTTP/1.0") != 0 && strcmp(protocol, "HTTP/1.1") != 0)) {
		static const char bad[] = "HTTP/1.0 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
		send_all(fd, bad, sizeof(bad) - 1);
		zsock_close(fd);
		return;
	}

	bool identity = strcmp(path, "/api/system") == 0 || strcmp(path, "/system/info") == 0;
	if (!identity && strcmp(path, "/") != 0) {
		static const char missing[] = "HTTP/1.0 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
		send_all(fd, missing, sizeof(missing) - 1);
		zsock_close(fd);
		return;
	}

	b_reset(&b, body, sizeof(body));
	if (identity) {
		build_identity_json(&b);
		send_all(fd, HDR_JSON, sizeof(HDR_JSON) - 1);
	} else {
		b_lit(&b, "<html><head><title>");
		b_lit(&b, CONFIG_APP_DEVICE_NAME);
		b_lit(&b, "</title></head><body><h1>");
		b_lit(&b, CONFIG_APP_DEVICE_NAME);
		b_lit(&b, "</h1><p>Zephyr RTOS sensor node. Identity: GET /api/system</p></body></html>\n");
		send_all(fd, HDR_HTML, sizeof(HDR_HTML) - 1);
	}
	send_all(fd, b.buf, b.len);
	zsock_close(fd);
}

static void server_loop(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1); ARG_UNUSED(p2); ARG_UNUSED(p3);
	struct sockaddr_in addr;
	int fd = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (fd < 0) {
		printk("socket failed: %d\n", errno);
		return;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(APP_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (zsock_bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
	    zsock_listen(fd, 2) < 0) {
		printk("bind/listen failed: %d\n", errno);
		zsock_close(fd);
		return;
	}
	printk("zephyr-sensor-01 http on :%d (uid %s fw %s)\n",
	       APP_PORT, CONFIG_APP_DEVICE_UID, CONFIG_APP_FW_VERSION);
	for (;;) {
		int client = zsock_accept(fd, NULL, NULL);
		if (client < 0) {
			k_sleep(K_MSEC(100));
			continue;
		}
		handle_client(client);
	}
}

static volatile bool ip_acquired;

/* DHCP 等待改为轮询：net_mgmt 回调签名在 v4.4 有变化，轮询更稳定 */
static bool check_ipv4_up(void)
{
	struct net_if *iface = net_if_get_default();
	if (iface == NULL) {
		return false;
	}
	struct net_in_addr *addr = net_if_ipv4_get_global_addr(iface, NET_ADDR_PREFERRED);
	return addr != NULL;
}

int main(void)
{
	/* Fail closed: do not expose a network service if host entropy is absent.
	 * Unequal samples are a plumbing check, not statistical RNG certification. */
	uint8_t sample_a[32], sample_b[32];
	if (sys_csrand_get(sample_a, sizeof(sample_a)) != 0 ||
	    sys_csrand_get(sample_b, sizeof(sample_b)) != 0 ||
	    memcmp(sample_a, sample_b, sizeof(sample_a)) == 0) {
		printk("entropy self-test failed; service disabled\n");
		return -EIO;
	}
	memset(sample_a, 0, sizeof(sample_a));
	memset(sample_b, 0, sizeof(sample_b));
	printk("zephyr-sensor-01 booting (board %s)\n", CONFIG_BOARD);
	net_dhcpv4_start(net_if_get_default());

	uint32_t waited = 0;
	while (!check_ipv4_up() && waited < 15000) {
		k_sleep(K_MSEC(500));
		waited += 500;
	}
	ip_acquired = check_ipv4_up();
	printk("%s: starting services\n",
	       ip_acquired ? "dhcp ok" : "dhcp timeout (services anyway)");

	k_thread_create(&sensor_thread, sensor_stack, K_THREAD_STACK_SIZEOF(sensor_stack),
			sensor_sim_loop, NULL, NULL, NULL, K_PRIO_PREEMPT(8), 0, K_NO_WAIT);
	k_thread_create(&server_thread, server_stack, K_THREAD_STACK_SIZEOF(server_stack),
			server_loop, NULL, NULL, NULL, K_PRIO_PREEMPT(7), 0, K_NO_WAIT);
	k_thread_name_set(&sensor_thread, "sensor_sim");
	k_thread_name_set(&server_thread, "http_server");
	return 0;
}
