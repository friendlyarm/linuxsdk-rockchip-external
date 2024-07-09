#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <alsa/asoundlib.h>
#include <pthread.h>

#include <RkBtBase.h>
#include <RkBtSink.h>
#include <RkBtSource.h>
#include <RkBle.h>
#include <RkBtSpp.h>
#include <RkBleClient.h>

//vendor code for broadcom
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <sys/ioctl.h>
enum{
	A2DP_SOURCE,
	A2DP_SINK
};

enum{
	ACL_NORMAL_PRIORITY,
	ACL_HIGH_PRIORITY
};
int vendor_set_high_priority(char *ba, uint8_t priority, uint8_t direction);
//vendor code for broadcom end


#include "bt_test.h"
#include "utility.h"

/* AD SERVICE_UUID */
#define AD_SERVICE_UUID16	"1111"
#define AD_SERVICE_UUID32	"00002222"
#define AD_SERVICE_UUID128	"00002222-0000-1000-8000-00805f9b34fb"

/* GAP/GATT Service UUID */
#define BLE_UUID_SERVICE	"00001111-0000-1000-8000-00805F9B34FB"
#define BLE_UUID_WIFI_CHAR	"00002222-0000-1000-8000-00805F9B34FB"
#define BLE_UUID_SEND		"dfd4416e-1810-47f7-8248-eb8be3dc47f9"
#define BLE_UUID_RECV		"9884d812-1810-4a24-94d3-b2c11a851fac"
#define SERVICE_UUID		"00001910-0000-1000-8000-00805f9b34fb"

#define BLE_UUID_SERVICE1	"00001234-0000-1000-8000-00805F9B34FB"
#define BLE_UUID_WIFI_CHAR1	"00001235-0000-1000-8000-00805F9B34FB"
#define BLE_UUID_SEND1		"00001336-1810-47f7-8248-eb8be3dc47f9"
#define BLE_UUID_RECV1		"00001337-1810-4a24-94d3-b2c11a851fac"
#define SERVICE_UUID1		"00001338-0000-1000-8000-00805f9b34fb"

static void bt_test_ble_recv_data_callback(const char *uuid, char *data, int *len, RK_BLE_GATT_STATE state);

/*
 * This structure must be initialized before use!
 *
 * The following variables will be updated by librkwifibt.so
 * bool init;
 * bool power;
 * bool pairable;
 * bool discoverable;
 * bool scanning;
 */
static RkBtContent bt_content;

/* BT base api */

/*
 * !!!Never write or call delaying or blocking code or functions within this function.
 * !!!切勿在此函数内编写或调用延迟或阻塞的代码或函数。
 *
 * !!!The rdev of some events is NULL. You must determine whether rdev is NULLL, otherwise a crash will occur.
 * !!!某些event的rdev是NULL，必须判断rdev是否为NULLL,否则会出现crash
 */
static void bt_test_state_cb(RkBtRemoteDev *rdev, RK_BT_STATE state)
{
	switch (state) {
	//BASE STATE
	case RK_BT_STATE_TURNING_ON:
		printf("++ RK_BT_STATE_TURNING_ON\n");
		break;
	case RK_BT_STATE_INIT_ON:
		printf("++ RK_BT_STATE_INIT_ON\n");
		bt_content.init = true;
		break;
	case RK_BT_STATE_INIT_OFF:
		printf("++ RK_BT_STATE_INIT_OFF\n");
		bt_content.init = false;
		break;

	//SCAN STATE
	case RK_BT_STATE_SCAN_NEW_REMOTE_DEV:
		if (rdev != NULL) {
			if (rdev->paired)
				printf("+ PAIRED_DEV: [%s|%d]:%s:%s\n", rdev->remote_address, rdev->rssi,
						rdev->remote_address_type, rdev->remote_alias);
			else
				printf("+ SCAN_NEW_DEV: [%s|%d]:%s:%s\n", rdev->remote_address, rdev->connected,
						rdev->remote_address_type, rdev->remote_alias);
		}
		break;
	case RK_BT_STATE_SCAN_CHG_REMOTE_DEV:
		if (rdev != NULL) {
			printf("+ SCAN_CHG_DEV: [%s|%d]:%s:%s|%s\n", rdev->remote_address, rdev->rssi,
					rdev->remote_address_type, rdev->remote_alias, rdev->change_name);

			if (!strcmp(rdev->change_name, "UUIDs")) {
				for (int index = 0; index < 36; index++) {
					if (!strcmp(rdev->remote_uuids[index], "NULL"))
						break;
					printf("\tUUIDs: %s\n", rdev->remote_uuids[index]);
				}
			} else if (!strcmp(rdev->change_name, "Icon")) {
				printf("\tIcon: %s\n", rdev->icon);
			} else if (!strcmp(rdev->change_name, "Class")) {
				printf("\tClass: 0x%x\n", rdev->cod);
			} else if (!strcmp(rdev->change_name, "Modalias")) {
				printf("\tModalias: %s\n", rdev->modalias);
			}
		}
		break;
	case RK_BT_STATE_SCAN_DEL_REMOTE_DEV:
		if (rdev != NULL)
			printf("+ SCAN_DEL_DEV: [%s]:%s:%s\n", rdev->remote_address,
					rdev->remote_address_type, rdev->remote_alias);
		break;

	//LINK STATE
	case RK_BT_STATE_CONNECTED:
	case RK_BT_STATE_DISCONN:
		if (rdev != NULL)
			printf("+ %s [%s|%d]:%s:%s\n", rdev->connected ? "STATE_CONNECTED" : "STATE_DISCONNECTED",
					rdev->remote_address,
					rdev->rssi,
					rdev->remote_address_type,
					rdev->remote_alias);
		break;
	case RK_BT_STATE_PAIRED:
	case RK_BT_STATE_PAIR_NONE:
		if (rdev != NULL)
			printf("+ %s [%s|%d]:%s:%s\n", rdev->paired ? "STATE_PAIRED" : "STATE_PAIR_NONE",
					rdev->remote_address,
					rdev->rssi,
					rdev->remote_address_type,
					rdev->remote_alias);
		break;
	case RK_BT_STATE_BONDED:
	case RK_BT_STATE_BOND_NONE:
		if (rdev != NULL)
			printf("+ %s [%s|%d]:%s:%s\n", rdev->bonded ? "STATE_BONDED" : "STATE_BOND_NONE",
				rdev->remote_address,
				rdev->rssi,
				rdev->remote_address_type,
				rdev->remote_alias);
		break;
	case RK_BT_STATE_DEL_DEV_OK:
		if (rdev != NULL)
			printf("+ RK_BT_STATE_DEL_DEV_OK: %s:%s:%s\n",
				rdev->remote_address,
				rdev->remote_address_type,
				rdev->remote_alias);
		break;
	case RK_BT_STATE_BOND_FAILED:
	case RK_BT_STATE_PAIR_FAILED:
		printf("+ STATE_BOND/PAIR FAILED\n");
		break;

	case RK_BT_STATE_CONNECT_FAILED:
		if (rdev != NULL)
			printf("+ STATE_FAILED [%s|%d]:%s:%s reason: %s\n",
					rdev->remote_address,
					rdev->rssi,
					rdev->remote_address_type,
					rdev->remote_alias,
					rdev->change_name);
		break;
	case RK_BT_STATE_DISCONN_ALREADY:
		printf("+ STATE_DISCONNECTED: RK_BT_STATE_DISCONN_ALREADY\n");
		break;
	case RK_BT_STATE_DISCONN_FAILED:
		printf("+ STATE_FAILED: RK_BT_STATE_DISCONN_FAILED\n");
		break;

	case RK_BT_STATE_CONNECTED_ALREADY:
		printf("+ STATE_CONNECTED: RK_BT_STATE_CONNECTED_ALREADY\n");
		break;
	case RK_BT_STATE_CONNECT_FAILED_INVAILD_ADDR:
		printf("+ STATE_FAILED: RK_BT_STATE_CONNECT_FAILED_INVAILD_ADDR\n");
		break;
	case RK_BT_STATE_CONNECT_FAILED_NO_FOUND_DEVICE:
		printf("+ STATE_FAILED: RK_BT_STATE_CONNECT_FAILED_NO_FOUND_DEVICE\n");
		break;
	case RK_BT_STATE_CONNECT_FAILED_SCANNING:
		printf("+ STATE_FAILED: RK_BT_STATE_CONNECT_FAILED_SCANNING\n");
		break;

	case RK_BT_STATE_DEL_DEV_FAILED:
		printf("+ STATE_FAILED: RK_BT_STATE_DEL_DEV_FAILED\n");
		break;

	//MEDIA A2DP SOURCE
	case RK_BT_STATE_SRC_ADD:
	case RK_BT_STATE_SRC_DEL:
		if (rdev != NULL) {
			printf("+ STATE SRC MEDIA %s [%s|%d]:%s:%s\n",
					(state == RK_BT_STATE_SRC_ADD) ? "ADD" : "DEL",
					rdev->remote_address,
					rdev->rssi,
					rdev->remote_address_type,
					rdev->remote_alias);
			printf("+ codec: %s, freq: %s, chn: %s\n",
						rdev->media.codec == 0 ? "SBC" : "UNKNOW",
						rdev->media.sbc.frequency == 1 ? "48K" : "44.1K",
						rdev->media.sbc.channel_mode == 1 ? "JOINT_STEREO" : "STEREO");
		}
		break;

	//MEDIA AVDTP TRANSPORT
	case RK_BT_STATE_TRANSPORT_VOLUME:
		if (rdev != NULL)
			printf("+ STATE AVDTP TRASNPORT VOLUME[%d] [%s|%d]:%s:%s\n",
					rdev->media.volume,
					rdev->remote_address,
					rdev->rssi,
					rdev->remote_address_type,
					rdev->remote_alias);
		break;
	case RK_BT_STATE_TRANSPORT_IDLE:
		if (rdev != NULL) {
			printf("+ STATE AVDTP TRASNPORT IDLE [%s|%d]:%s:%s\n",
					rdev->remote_address,
					rdev->rssi,
					rdev->remote_address_type,
					rdev->remote_alias);
			//low priority for broadcom
			vendor_set_high_priority(rdev->remote_address, ACL_NORMAL_PRIORITY,
									 bt_content.profile & PROFILE_A2DP_SINK_HF ? A2DP_SINK : A2DP_SOURCE);
		}
		break;
	case RK_BT_STATE_TRANSPORT_PENDING:
		if (rdev != NULL)
			printf("+ STATE AVDTP TRASNPORT PENDING [%s|%d]:%s:%s\n",
				rdev->remote_address,
				rdev->rssi,
				rdev->remote_address_type,
				rdev->remote_alias);
		break;
	case RK_BT_STATE_TRANSPORT_ACTIVE:
		if (rdev != NULL) {
			printf("+ STATE AVDTP TRASNPORT ACTIVE [%s|%d]:%s:%s\n",
				rdev->remote_address,
				rdev->rssi,
				rdev->remote_address_type,
				rdev->remote_alias);
			//high priority for broadcom
			vendor_set_high_priority(rdev->remote_address, ACL_HIGH_PRIORITY,
								 bt_content.profile & PROFILE_A2DP_SINK_HF ? A2DP_SINK : A2DP_SOURCE);
		}
		break;
	case RK_BT_STATE_TRANSPORT_SUSPENDING:
		if (rdev != NULL)
			printf("+ STATE AVDTP TRASNPORT SUSPEND [%s|%d]:%s:%s\n",
				rdev->remote_address,
				rdev->rssi,
				rdev->remote_address_type,
				rdev->remote_alias);
		break;

	//MEDIA A2DP SINK
	case RK_BT_STATE_SINK_ADD:
	case RK_BT_STATE_SINK_DEL:
		if (rdev != NULL) {
			printf("+ STATE SINK MEDIA %s [%s|%d]:%s:%s\n",
				(state == RK_BT_STATE_SINK_ADD) ? "ADD" : "DEL",
				rdev->remote_address,
				rdev->rssi,
				rdev->remote_address_type,
				rdev->remote_alias);
			printf("+ codec: %s, freq: %s, chn: %s\n",
					rdev->media.codec == 0 ? "SBC" : "UNKNOW",
					rdev->media.sbc.frequency == 1 ? "48K" : "44.1K",
					rdev->media.sbc.channel_mode == 1 ? "JOINT_STEREO" : "STEREO");
		}
		break;
	case RK_BT_STATE_SINK_PLAY:
		if (rdev != NULL)
			printf("+ STATE SINK PLAYER PLAYING [%s|%d]:%s:%s\n",
				rdev->remote_address,
				rdev->rssi,
				rdev->remote_address_type,
				rdev->remote_alias);
		break;
	case RK_BT_STATE_SINK_STOP:
		if (rdev != NULL)
			printf("+ STATE SINK PLAYER STOP [%s|%d]:%s:%s\n",
				rdev->remote_address,
				rdev->rssi,
				rdev->remote_address_type,
				rdev->remote_alias);
		break;
	case RK_BT_STATE_SINK_PAUSE:
		if (rdev != NULL)
			printf("+ STATE SINK PLAYER PAUSE [%s|%d]:%s:%s\n",
				rdev->remote_address,
				rdev->rssi,
				rdev->remote_address_type,
				rdev->remote_alias);
		break;
    case RK_BT_STATE_SINK_TRACK:
        printf("+ STATE SINK TRACK INFO [%s|%d]:%s:%s track[%s]-[%s]\n",
            rdev->remote_address,
            rdev->rssi,
            rdev->remote_address_type,
            rdev->remote_alias,
            rdev->title,
            rdev->artist);
    break;
    case RK_BT_STATE_SINK_POSITION:
        printf("+ STATE SINK TRACK POSITION:[%s|%d]:%s:%s [%u-%u]\n",
                rdev->remote_address,
                rdev->rssi,
                rdev->remote_address_type,
                rdev->remote_alias,
                rdev->player_position,
                rdev->player_total_len);
    break;

	//ADV
	case RK_BT_STATE_ADAPTER_BLE_ADV_START:
		bt_content.ble_content.ble_advertised = true;
		printf("RK_BT_STATE_ADAPTER_BLE_ADV_START successful\n");
		break;
	case RK_BT_STATE_ADAPTER_BLE_ADV_STOP:
		bt_content.ble_content.ble_advertised = false;
		printf("RK_BT_STATE_ADAPTER_BLE_ADV_STOP successful\n");
		break;

	//ADAPTER STATE
	case RK_BT_STATE_ADAPTER_NO_DISCOVERYABLED:
		bt_content.discoverable = false;
		printf("RK_BT_STATE_ADAPTER_NO_DISCOVERYABLED successful\n");
		break;
	case RK_BT_STATE_ADAPTER_DISCOVERYABLED:
		bt_content.discoverable = true;
		printf("RK_BT_STATE_ADAPTER_DISCOVERYABLED successful\n");
		break;
	case RK_BT_STATE_ADAPTER_NO_PAIRABLED:
		bt_content.pairable = false;
		printf("RK_BT_STATE_ADAPTER_NO_PAIRABLED successful\n");
		break;
	case RK_BT_STATE_ADAPTER_PAIRABLED:
		bt_content.pairable = true;
		printf("RK_BT_STATE_ADAPTER_PAIRABLED successful\n");
		break;
	case RK_BT_STATE_ADAPTER_NO_SCANNING:
		bt_content.scanning = false;
		printf("RK_BT_STATE_ADAPTER_NO_SCANNING successful\n");
		break;
	case RK_BT_STATE_ADAPTER_SCANNING:
		bt_content.scanning = true;
		printf("RK_BT_STATE_ADAPTER_SCANNING successful\n");
		break;
	case RK_BT_STATE_ADAPTER_POWER_ON:
		bt_content.power = true;
		printf("RK_BT_STATE_ADAPTER_POWER_ON successful\n");
		break;
	case RK_BT_STATE_ADAPTER_POWER_OFF:
		bt_content.power = false;
		printf("RK_BT_STATE_ADAPTER_POWER_OFF successful\n");
		break;

	case RK_BT_STATE_COMMAND_RESP_OK:
		printf("RK_BT_STATE CMD OK\n");
		break;
	case RK_BT_STATE_COMMAND_RESP_ERR:
		printf("RK_BT_STATE CMD ERR\n");
		break;

	default:
		if (rdev != NULL)
			printf("+ DEFAULT STATE %d: %s:%s:%s RSSI: %d [CBP: %d:%d:%d]\n", state,
				rdev->remote_address,
				rdev->remote_address_type,
				rdev->remote_alias,
				rdev->rssi,
				rdev->connected,
				rdev->paired,
				rdev->bonded);
		break;
	}
}

void bt_test_version(char *data)
{
	printf("RK BT VERSION: %s\n", rk_bt_version());
}

void bt_test_source_play(char *data)
{
	char rsp[64], aplay[128];
	exec_command("hcitool con | grep ACL | awk '{print $3}'", rsp, 64);
	if (rsp[0]) {
		rsp[17] = 0;
		sprintf(aplay, "aplay -D bluealsa:DEV=%s,PROFILE=a2dp /data/test.wav", rsp);
		exec_command_system(aplay);
	}
}

static bool bt_test_audio_server_cb(void)
{
	char rsp[64];

	printf("%s bt_content.profile: 0x%x:0x%x:0x%x\n", __func__, bt_content.profile,
			(bt_content.profile & PROFILE_A2DP_SINK_HF),
			(bt_content.profile & PROFILE_A2DP_SOURCE_AG));

	if (bt_content.bluealsa == true) {
		//use bluealsa
		//exec_command("pactl list modules | grep bluetooth | grep policy", rsp, 64);
		exec_command("pactl list modules | grep bluetooth", rsp, 64);
		if (rsp[0]) {
			exec_command_system("pactl unload-module module-bluetooth-policy");
			exec_command_system("pactl unload-module module-bluetooth-discover");
		}

		exec_command_system("killall bluealsa bluealsa-aplay");

		if ((bt_content.profile & PROFILE_A2DP_SINK_HF) == PROFILE_A2DP_SINK_HF) {
			exec_command_system("bluealsa -S --profile=a2dp-sink --profile=hfp-hf &");
			//Sound Card: default
			exec_command_system("bluealsa-aplay -S --profile-a2dp 00:00:00:00:00:00 &");
		} else if ((bt_content.profile & PROFILE_A2DP_SOURCE_AG) == PROFILE_A2DP_SOURCE_AG) {
			exec_command_system("bluealsa -S --profile=a2dp-source --profile=hfp-ag --a2dp-volume &");
		}
	}

	return true;
}

static bool bt_test_vendor_cb(bool enable)
{
	int times = 100;

	if (enable) {
		//vendor
		//broadcom
		if (get_ps_pid("brcm_patchram_plus1"))
			kill_task("brcm_patchram_plus1");

		//realtek
		if (get_ps_pid("rtk_hciattach"))
			kill_task("rtk_hciattach");

		//The hci0 start to init ...
		if (!access("/usr/bin/wifibt-init.sh", F_OK))
			exec_command_system("/usr/bin/wifibt-init.sh start_bt");
		else if (!access("/usr/bin/bt_init.sh", F_OK))
			exec_command_system("/usr/bin/bt_init.sh");

		//wait hci0 appear
		while (times-- > 0 && access("/sys/class/bluetooth/hci0", F_OK)) {
			usleep(100 * 1000);
		}

		if (access("/sys/class/bluetooth/hci0", F_OK) != 0) {
			printf("The hci0 init failure!\n");
			return false;
		}

		/* ensure bluetoothd running */
		/*
		 * DEBUG: vim /etc/init.d/S40bluetooth, modify BLUETOOTHD_ARGS="-n -d"
		 */
		if (access("/etc/init.d/S40bluetooth", F_OK) == 0)
			exec_command_system("/etc/init.d/S40bluetooth restart");
		else if (access("/etc/init.d/S40bluetoothd", F_OK) == 0)
			exec_command_system("/etc/init.d/S40bluetoothd restart");

		//or
		//exec_command_system("/usr/libexec/bluetoothd -n -P battery");
		//or debug
		//exec_command_system("/usr/libexec/bluetoothd -n -P battery -d");
		//exec_command_system("hcidump xxx or btmon xxx");

		//check bluetoothd
		times = 100;
		while (times-- > 0 && !(get_ps_pid("bluetoothd"))) {
			usleep(100 * 1000);
		}

		if (!get_ps_pid("bluetoothd")) {
			printf("The bluetoothd boot failure!\n");
			return false;
		}
	} else {
		//CLEAN
		exec_command_system("hciconfig hci0 down");
		exec_command_system("/etc/init.d/S40bluetooth stop");

		//vendor deinit
		if (get_ps_pid("brcm_patchram_plus1"))
			kill_task("killall brcm_patchram_plus1");
		if (get_ps_pid("rtk_hciattach"))
			kill_task("killall rtk_hciattach");

		//audio server deinit
		if (get_ps_pid("bluealsa"))
			kill_task("bluealsa");
		if (get_ps_pid("bluealsa-alay"))
			kill_task("bluealsa-alay");
	}

	return true;
}

#include <sys/time.h>
struct timeval start, now;
static ssize_t totalBytes;

/* bt init */
void *bt_test_init(void *arg)
{
	RkBleGattService *gatt;
	//"indicate"
	//static char *chr_props[] = { "read", "write", "notify", "write-without-response", "encrypt-read", NULL };
	static char *chr_props[] = { "read", "write", "notify", "write-without-response", NULL };

	printf("%s \n", __func__);

	//Must determine whether Bluetooth is turned on
	if (rk_bt_is_open()) {
		printf("%s: already open \n", __func__);
		return NULL;
	}

	memset(&bt_content, 0, sizeof(RkBtContent));

	//BREDR CLASS BT NAME
	bt_content.bt_name = "SCO_AUDIO";

	//BLE NAME
	bt_content.ble_content.ble_name = "RBLE";

	//IO CAPABILITY
	bt_content.io_capability = IO_CAPABILITY_DISPLAYYESNO;

	/*
	 * Only one can be enabled
	 * a2dp sink and hfp-hf
	 * a2dp source and hfp-ag
	 */
	bt_content.profile = PROFILE_A2DP_SINK_HF;
	bt_content.bluealsa = true;

	// enable ble
	bt_content.profile |= PROFILE_BLE;
	if (bt_content.profile & PROFILE_BLE) {
		/* GATT SERVICE/CHARACTERISTIC */
		//SERVICE_UUID
		gatt = &(bt_content.ble_content.gatt_instance[0]);
		gatt->server_uuid.uuid = SERVICE_UUID;
		gatt->chr_uuid[0].uuid = BLE_UUID_SEND;
		gatt->chr_uuid[0].chr_props = chr_props;

		gatt->chr_uuid[1].uuid = BLE_UUID_RECV;
		gatt->chr_uuid[1].chr_props = chr_props;
		gatt->chr_cnt = 2;

		//SERVICE_UUID1
		gatt = &(bt_content.ble_content.gatt_instance[1]);
		gatt->server_uuid.uuid = SERVICE_UUID1;
		gatt->chr_uuid[0].uuid = BLE_UUID_SEND1;
		gatt->chr_uuid[0].chr_props = chr_props;
		gatt->chr_uuid[1].uuid = BLE_UUID_RECV1;
		gatt->chr_uuid[1].chr_props = chr_props;
		gatt->chr_cnt = 2;

		bt_content.ble_content.srv_cnt = 2;

		/* Fill adv data */
		/* Appearance */
		bt_content.ble_content.Appearance = 0x0080;

		/* manufacturer data */
		bt_content.ble_content.manufacturer_id = 0x0059;
		for (int i = 0; i < 16; i++)
			bt_content.ble_content.manufacturer_data[i] = i;

		/* Service UUID */
		bt_content.ble_content.adv_server_uuid.uuid = AD_SERVICE_UUID16;

		//callback
		bt_content.ble_content.cb_ble_recv_fun = bt_test_ble_recv_data_callback;
	}

	rk_bt_register_state_callback(bt_test_state_cb);
	rk_bt_register_vendor_callback(bt_test_vendor_cb);
	rk_bt_register_audio_server_callback(bt_test_audio_server_cb);

	//default state
	bt_content.init = false;

	rk_bt_init(&bt_content);

	// 初始化时间和计数器
	gettimeofday(&start, NULL);
	ssize_t totalBytes = 0;

	return NULL;
}

void bt_test_bluetooth_onoff_init(char *data)
{
	int test_cnt = 5000, cnt = 0;

	if (data)
		test_cnt = atoi(data);
	printf("%s test times: %d(%d)\n", __func__, test_cnt, data ? atoi(data) : 0);

	while (cnt < test_cnt) {
		printf("BT TEST INIT START\n");
		bt_test_init(NULL);
		while (bt_content.init == false) {
			sleep(1);
			printf("BT TURNING ON ...\n");
		}

		//scan test
		rk_bt_start_discovery(SCAN_TYPE_AUTO);
		while (bt_content.scanning == false) {
			sleep(1);
			printf("BT SCAN ON ...\n");
		}
		sleep(10);
		rk_bt_cancel_discovery();
		while (bt_content.scanning == true) {
			sleep(1);
			printf("BT SCAN OFF ...\n");
		}

		//ble adv tests
		rk_ble_adv_start();
		while (bt_content.ble_content.ble_advertised == false) {
			sleep(1);
			printf("BT ADV ON ...\n");
		}
		sleep(3);
		rk_ble_adv_stop();
		while (bt_content.ble_content.ble_advertised == true) {
			sleep(1);
			printf("BT ADV OFF ...\n");
		}

		rk_bt_deinit();
		while (bt_content.init == true) {
			sleep(1);
			printf("BT TURNING OFF ...\n");
		}
		printf("BT INIT/ADV/SCAN CNTs: [====== %d ======] \n", ++cnt);
	}
}

void bt_test_bluetooth_init(char *data)
{
	bt_test_init(NULL);

	return;
}

void bt_test_bluetooth_deinit(char *data)
{
	rk_bt_deinit();

	return;
}

void bt_test_get_adapter_info(char *data)
{
	rk_bt_adapter_info(data);
}

void bt_test_connect_by_addr(char *data)
{
	rk_bt_connect_by_addr(data);
}

void bt_test_disconnect_by_addr(char *data)
{
	rk_bt_disconnect_by_addr(data);
}

void bt_test_pair_by_addr(char *data)
{
	rk_bt_pair_by_addr(data);
}

void bt_test_unpair_by_addr(char *data)
{
	rk_bt_unpair_by_addr(data);
}

void bt_test_start_discovery(char *data)
{
	RK_BT_SCAN_TYPE type;

	if (data == NULL) {
		rk_bt_start_discovery(SCAN_TYPE_AUTO);
		return;
	}

	if (!strcmp(data, "bredr"))
		type = SCAN_TYPE_BREDR;
	else if (!strcmp(data, "le"))
		type = SCAN_TYPE_LE;
	else
		type = SCAN_TYPE_AUTO;

	rk_bt_start_discovery(type);
}

void bt_test_cancel_discovery(char *data)
{
	if (bt_content.scanning == false)
		return;

	rk_bt_cancel_discovery();
}

void bt_test_set_discoverable(char *data)
{
	bool enable;

	if (data == NULL)
		return;

	if (!strcmp(data, "on"))
		enable = 1;
	else if (!strcmp(data, "off"))
		enable = 0;
	else
		return;

	rk_bt_set_discoverable(enable);
}

void bt_test_set_pairable(char *data)
{
	bool enable;

	if (data == NULL)
		return;

	if (!strcmp(data, "on"))
		enable = 1;
	else if (!strcmp(data, "off"))
		enable = 0;
	else
		return;

	rk_bt_set_pairable(enable);
}

void bt_test_set_power(char *data)
{
	bool enable;

	if (data == NULL)
		return;

	if (!strcmp(data, "on"))
		enable = 1;
	else if (!strcmp(data, "off"))
		enable = 0;
	else
		return;

	rk_bt_set_power(enable);
}

void bt_test_get_all_devices(char *data)
{
	int i, count;
	struct remote_dev *rdev = NULL;

	//Get all devices
	if (bt_get_devices(&rdev, &count) < 0) {
		printf("Can't get scan list!");
		return;
	}

	printf("rdev: %p\n", rdev);
	for (i = 0; i < count; i++) {
		if (rdev[i].connected)
			printf("Connected Device %s (%s:%s)\n",
					rdev[i].remote_address,
					rdev[i].remote_address_type,
					rdev[i].remote_alias);
		else
			printf("%s Device %s (%s:%s)\n",
				rdev[i].paired ? "Paired" : "Scaned",
				rdev[i].remote_address,
				rdev[i].remote_address_type,
				rdev[i].remote_alias);
	}
}

void bt_test_read_remote_device_info(char *data)
{
	struct remote_dev rdev;
	char *t_addr = data;

	if (bt_get_dev_info(&rdev, t_addr) < 0)
		return;

	printf("Device info: addr:%s:%s, name: %s, class:(0x%x:0x%x), RSSI: %d\n",
			rdev.remote_address,
			rdev.remote_address_type,
			rdev.remote_alias,
			rdev.cod,
			rdev.appearance,
			rdev.rssi);

	for (int index = 0; index < 10; index++) {
		if (!strcmp(rdev.remote_uuids[index], "NULL"))
			break;
		printf("	UUIDs: %s\n", rdev.remote_uuids[index]);
	}
}

/******************************************/
/*               A2DP SINK                */
/******************************************/
void bt_test_sink_media_control(char *data)
{
	rk_bt_sink_media_control(data);
}

void bt_test_a2dp_test_volume(char *data)
{
	if (data) {
		printf("===== A2DP Set Volume: %d =====\n", atoi(data));
		rk_bt_sink_set_volume(atoi(data));
	}
}

void bt_test_enable_a2dp_source(char *data)
{
	rk_bt_set_profile(PROFILE_A2DP_SOURCE_AG);
}

void bt_test_enable_a2dp_sink(char *data)
{
	rk_bt_set_profile(PROFILE_A2DP_SINK_HF);
}

/******************************************/
/*                  BLE                   */
/******************************************/

static void bt_test_ble_recv_data_callback(const char *uuid, char *data, int *len, RK_BLE_GATT_STATE state)
{
	switch (state) {
	//SERVER ROLE
	case RK_BLE_GATT_SERVER_READ_BY_REMOTE:
		//The remote dev reads characteristic and put data to *data.
		printf("+++ ble server is read by remote uuid: %s\n", uuid);
		*len = strlen("hello rockchip");
		memcpy(data, "hello rockchip", strlen("hello rockchip"));
		break;
	case RK_BLE_GATT_SERVER_WRITE_BY_REMOTE:
		//The remote dev writes data to characteristic so print there.
		printf("+++ ble server is writeen by remote uuid: %s\n", uuid);
		for (int i = 0 ; i < *len; i++) {
			printf("%02x ", data[i]);
		}
		printf("\n");
		break;
	case RK_BLE_GATT_SERVER_ENABLE_NOTIFY_BY_REMOTE:
	case RK_BLE_GATT_SERVER_DISABLE_NOTIFY_BY_REMOTE:
		//The remote dev enable notify for characteristic
		printf("+++ ble server notify is %s by remote uuid: %s\n",
				(state == RK_BLE_GATT_SERVER_ENABLE_NOTIFY_BY_REMOTE) ? "enable" : "disabled",
				uuid);
		break;
	case RK_BLE_GATT_MTU:
		//
		printf("+++ ble server MTU: %d ===\n", *(uint16_t *)data);
		break;
	case RK_BLE_GATT_SERVER_INDICATE_RESP_BY_REMOTE:
		//The service sends notify to remote dev and recv indicate from remote dev.
		printf("+++ ble server receive remote indicate resp uuid: %s\n", uuid);
		break;

	//CLIENT ROLE
	case RK_BLE_GATT_SERVER_READ_NOT_PERMIT_BY_REMOTE:
		//error handle: org.bluez.Error.NotPermitted
		printf("+++ ble client recv error: %s +++\n", data);
	case RK_BLE_GATT_CLIENT_READ_BY_LOCAL:
		//printf("+++ ble client recv from remote data uuid: %s:%d===\n", uuid, *len);
		//for (int i = 0 ; i < *len; i++) {
		//	printf("%02x ", data[i]);
		//}
		//printf("\n");
		//printf("%02x %02x %02x \n", data[0], data[123], data[246]);
		totalBytes += *len * 8; // 转换为位
		gettimeofday(&now, NULL);
		long elapsed = (now.tv_sec - start.tv_sec) * 1000000 + now.tv_usec - start.tv_usec;
		if (elapsed >= 1000000) { // 每秒计算一次
			printf("Rate: %ld bits/sec [%s]\n", totalBytes / (elapsed / 1000000), uuid);
			totalBytes = 0; // 重置计数器
			start = now; // 重置时间
		}
		break;
	case RK_BLE_GATT_CLIENT_WRITE_RESP_BY_LOCAL:
		break;
	case RK_BLE_GATT_CLIENT_NOTIFY_ENABLE:
	case RK_BLE_GATT_CLIENT_NOTIFY_DISABLE:
		printf("+++ ble client uuid: %s notify is %s \n",
				uuid,
				(state == RK_BLE_GATT_CLIENT_NOTIFY_ENABLE) ? "enable" : "disabled"
				);
		break;
	default:
		break;
	}
}

void bt_test_ble_start(char *data)
{
	rk_ble_adv_start();
}

void bt_test_ble_set_adv_interval(char *data)
{
	//default 100ms, test: 20ms(32 * 0.625) ~ 100ms(160 * 0.625)
	rk_ble_set_adv_interval(32, 160);
}

void bt_test_ble_write(char *data)
{
	rk_ble_send_notify(BLE_UUID_SEND, data, strlen(data));
}

void bt_test_ble_get_status(char *data)
{

}

void bt_test_ble_stop(char *data) {
	rk_ble_adv_stop();
}

/******************************************/
/*               BLE CLIENT               */
/******************************************/
void bt_test_ble_client_get_service_info(char *data)
{
	int i, j, k;
	RK_BLE_CLIENT_SERVICE_INFO info;

	if (!rk_ble_client_get_service_info(data, &info)) {
		printf("+++++ get device(%s) service info +++++\n", data);
		for(i = 0; i < info.service_cnt; i++) {
			printf("service[%d]:\n", i);
			printf("	describe: %s\n", info.service[i].describe);
			printf("	path: %s\n", info.service[i].path);
			printf("	uuid: %s\n", info.service[i].uuid);

			for(j = 0; j < info.service[i].chrc_cnt; j++) {
				printf("	characteristic[%d]:\n", j);
				printf("		describe: %s\n", info.service[i].chrc[j].describe);
				printf("		path: %s\n", info.service[i].chrc[j].path);
				printf("		uuid: %s\n", info.service[i].chrc[j].uuid);
				printf("		props: 0x%x\n", info.service[i].chrc[j].props);
				printf("		ext_props: 0x%x\n", info.service[i].chrc[j].ext_props);
				printf("		perm: 0x%x\n", info.service[i].chrc[j].perm);
				printf("		notifying: %d\n", info.service[i].chrc[j].notifying);

				for(k = 0; k < info.service[i].chrc[j].desc_cnt; k++) {
					printf("		descriptor[%d]:\n", k);

					printf("			describe: %s\n", info.service[i].chrc[j].desc[k].describe);
					printf("			path: %s\n", info.service[i].chrc[j].desc[k].path);
					printf("			uuid: %s\n", info.service[i].chrc[j].desc[k].uuid);
				}
			}
		}
	}
}

void bt_test_ble_client_read(char *data)
{
	rk_ble_client_read(data);
}

void bt_test_ble_client_write(char *data)
{
	char *write_buf = "hello world";

	rk_ble_client_write(data, write_buf, strlen("hello world"));
}

void bt_test_ble_client_is_notify(char *data)
{
	bool notifying;

	notifying = rk_ble_client_is_notifying(data);
	printf("%s notifying %s\n", data, notifying ? "yes" : "no");
}

void bt_test_ble_client_notify_on(char *data)
{
	rk_ble_client_notify(data, true);
}

void bt_test_ble_client_notify_off(char *data)
{
	rk_ble_client_notify(data, false);
}

/******************************************/
/*                  SPP                   */
/******************************************/
void _btspp_status_callback(RK_BT_SPP_STATE type)
{
	switch(type) {
	case RK_BT_SPP_STATE_IDLE:
		printf("+++++++ RK_BT_SPP_STATE_IDLE +++++\n");
		break;
	case RK_BT_SPP_STATE_CONNECT:
		printf("+++++++ RK_BT_SPP_EVENT_CONNECT +++++\n");
		break;
	case RK_BT_SPP_STATE_DISCONNECT:
		printf("+++++++ RK_BT_SPP_EVENT_DISCONNECT +++++\n");
		break;
	default:
		printf("+++++++ BT SPP NOT SUPPORT TYPE! +++++\n");
		break;
	}
}

void _btspp_recv_callback(char *data, int len)
{
	if (len) {
		printf("+++++++ RK BT SPP RECV DATA: +++++\n");
		printf("\tRECVED(%d):%s\n", len, data);
	}
}

void bt_test_spp_open(char *data)
{
	rk_bt_spp_open(data);
	rk_bt_spp_register_status_cb(_btspp_status_callback);
	rk_bt_spp_register_recv_cb(_btspp_recv_callback);
}

void bt_test_spp_write(char *data)
{
	unsigned int ret = 0;
	//char buff[100] = {"This is a message from rockchip board!"};

	ret = rk_bt_spp_write(data, strlen(data));
	if (ret < 0) {
		printf("%s failed\n", __func__);
	}
}

void bt_test_spp_connect(char *data)
{
	rk_bt_spp_connect(data);
}

void bt_test_spp_disconnect(char *data)
{
	rk_bt_spp_disconnect(data);
}

void bt_test_spp_listen(char *data)
{
	rk_bt_spp_listen();
}

void bt_test_spp_close(char *data)
{
	rk_bt_spp_close();
}

void bt_test_spp_status(char *data)
{
	RK_BT_SPP_STATE status;

	rk_bt_spp_get_state(&status);
	switch(status) {
	case RK_BT_SPP_STATE_IDLE:
		printf("+++++++ RK_BT_SPP_STATE_IDLE +++++\n");
		break;
	case RK_BT_SPP_STATE_CONNECT:
		printf("+++++++ RK_BT_SPP_STATE_CONNECT +++++\n");
		break;
	case RK_BT_SPP_STATE_DISCONNECT:
		printf("+++++++ RK_BT_SPP_STATE_DISCONNECT +++++\n");
		break;
	default:
		printf("+++++++ BTSPP NO STATUS SUPPORT! +++++\n");
		break;
	}
}

/**
 * VENDOR CODE
 */
static int write_flush_timeout(int fd, uint16_t handle,
		unsigned int timeout_ms)
{
	uint16_t timeout = (timeout_ms * 1000) / 625;  // timeout units of 0.625ms
	unsigned char hci_write_flush_cmd[] = {
		0x01,               // HCI command packet
		0x28, 0x0C,         // HCI_Write_Automatic_Flush_Timeout
		0x04,               // Length
		0x00, 0x00,         // Handle
		0x00, 0x00,         // Timeout
	};

	hci_write_flush_cmd[4] = (uint8_t)handle;
	hci_write_flush_cmd[5] = (uint8_t)(handle >> 8);
	hci_write_flush_cmd[6] = (uint8_t)timeout;
	hci_write_flush_cmd[7] = (uint8_t)(timeout >> 8);

	int ret = write(fd, hci_write_flush_cmd, sizeof(hci_write_flush_cmd));
	if (ret < 0) {
		printf("write(): %s (%d)]", strerror(errno), errno);
		return -1;
	} else if (ret != sizeof(hci_write_flush_cmd)) {
		printf("write(): unexpected length %d", ret);
		return -1;
	}
	return 0;
}

static int vendor_high_priority(int fd, uint16_t handle,uint8_t priority, uint8_t direction)
{
	unsigned char hci_high_priority_cmd[] = {
		0x01,               // HCI command packet
		0x1a, 0xfd,         // Write_A2DP_Connection
		0x04,               // Length
		0x00, 0x00,         // Handle
		0x00, 0x00          // Priority, Direction 
	};

	hci_high_priority_cmd[4] = (uint8_t)handle;
	hci_high_priority_cmd[5] = (uint8_t)(handle >> 8);
	hci_high_priority_cmd[6] = (uint8_t)priority;
	hci_high_priority_cmd[7] = (uint8_t)direction; 

	int ret = write(fd, hci_high_priority_cmd, sizeof(hci_high_priority_cmd));
	if (ret < 0) {
		printf("write(): %s (%d)]", strerror(errno), errno);
		return -1;
	} else if (ret != sizeof(hci_high_priority_cmd)) {
		printf("write(): unexpected length %d", ret);
		return -1;
	}
	return 0;
}


static int get_hci_sock(void)
{
	int sock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	struct sockaddr_hci addr;
	int opt;

	if (sock < 0) {
		printf("Can't create raw HCI socket!");
		return -1;
	}

	opt = 1;
	if (setsockopt(sock, SOL_HCI, HCI_DATA_DIR, &opt, sizeof(opt)) < 0) {
		printf("Error setting data direction\n");
		return -1;
	}

	/* Bind socket to the HCI device */
	memset(&addr, 0, sizeof(addr));
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = 0;  // hci0
	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		printf("Can't attach to device hci0. %s(%d)\n",
				strerror(errno),
				errno);
		return -1;
	}
	return sock;
}


static int get_acl_handle(int fd, char *bdaddr) {
	int i;
	int ret = -1;
	struct hci_conn_list_req *conn_list;
	struct hci_conn_info *conn_info;
	int max_conn = 10;
	char addr[18];

	conn_list = malloc(max_conn * (
		sizeof(struct hci_conn_list_req) + sizeof(struct hci_conn_info)));
	if (!conn_list) {
		printf("Out of memory in %s\n", __FUNCTION__);
		return -1;
	}

	conn_list->dev_id = 0;  /* hardcoded to HCI device 0 */
	conn_list->conn_num = max_conn;

	if (ioctl(fd, HCIGETCONNLIST, (void *)conn_list)) {
		printf("Failed to get connection list\n");
		goto out;
	}
	printf("XXX %d\n", conn_list->conn_num);

	for (i=0; i < conn_list->conn_num; i++) {
		conn_info = &conn_list->conn_info[i];
		memset(addr, 0, 18);
		sprintf(addr, "%02x:%02x:%02x:%02x:%02x:%02x",
				conn_info->bdaddr.b[5],
				conn_info->bdaddr.b[4],
				conn_info->bdaddr.b[3],
				conn_info->bdaddr.b[2],
				conn_info->bdaddr.b[1],
				conn_info->bdaddr.b[0]);
		printf("XXX %d %s:%s\n", conn_info->type, bdaddr, addr);
		if (conn_info->type == ACL_LINK &&
				!strcasecmp(addr, bdaddr)) {
			ret = conn_info->handle;
			goto out;
		}
	}

	ret = 0;

out:
	free(conn_list);
	return ret;
}


/* Request that the ACL link to a given Bluetooth connection be high priority,
 * for improved coexistance support
 */
int vendor_set_high_priority(char *ba, uint8_t priority, uint8_t direction)
{
	int ret;
	int fd = get_hci_sock();
	int acl_handle;

	if (fd < 0)
		return fd;

	acl_handle = get_acl_handle(fd, ba);
	if (acl_handle <= 0) {
		ret = acl_handle;
		goto out;
	}

	ret = vendor_high_priority(fd, acl_handle, priority, direction);
	if (ret < 0)
		goto out;
	ret = write_flush_timeout(fd, acl_handle, 200);

out:
	close(fd);

	return ret;
}
