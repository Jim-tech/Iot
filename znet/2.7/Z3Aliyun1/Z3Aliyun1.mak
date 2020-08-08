# Architecture directories
ARCHITECTURE_DIR = efr32
BUILD_DIR = build
OUTPUT_DIR = $(BUILD_DIR)/$(ARCHITECTURE_DIR)
LST_DIR = lst
PROJECTNAME = Z3Aliyun1

# Stack and submodule directories
GLOBAL_BASE_DIR     = ../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/..

SOURCE_FILES = \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emdrv/dmadrv/src/dmadrv.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emdrv/gpiointerrupt/src/gpiointerrupt.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../service/sleeptimer/src/sl_sleeptimer.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../service/sleeptimer/src/sl_sleeptimer_hal_rtcc.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emdrv/sleep/src/sleep.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emdrv/tempdrv/src/tempdrv.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emdrv/ustimer/src/ustimer.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emlib/src/em_adc.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emlib/src/em_cmu.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emlib/src/em_core.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emlib/src/em_cryotimer.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emlib/src/em_emu.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emlib/src/em_eusart.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emlib/src/em_gpio.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emlib/src/em_i2c.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emlib/src/em_ldma.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emlib/src/em_leuart.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emlib/src/em_msc.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emlib/src/em_prs.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emlib/src/em_rmu.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emlib/src/em_rtcc.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emlib/src/em_se.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emlib/src/em_system.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emlib/src/em_timer.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emlib/src/em_usart.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emlib/src/em_wdog.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../Device/SiliconLabs/EFR32MG12P/Source/system_efr32mg12p.c \
./znet-bookkeeping.c \
./call-command-handler.c \
./callback-stub.c \
./stack-handler-stub.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/cortexm3/efm32/assert-crash-handlers.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/cortexm3/efm32/button.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/plugin/buzzer/buzzer-efr32.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/../util/serial/command-interpreter2.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/generic/crc.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/cortexm3/efm32/cstartup-common.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/cortexm3/efm32/diagnostic.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/../../stack/config/ember-configuration.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/generic/endian.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/cortexm3/efm32/faults-v7m.s79 \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/cortexm3/efm32/isr-stubs.s79 \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/cortexm3/efm32/led.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/../util/common/library.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/generic/mem-util.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/cortexm3/efm32/mfg-token.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/cortexm3/efm32/micro-common.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/cortexm3/efm32/micro.c \
./znet-cli.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/generic/random.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/../util/security/security-address-cache.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/ember-base-configuration.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/cortexm3/efm32/sleep-efm32.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/generic/token-def.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/cortexm3/efm32/token.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/cortexm3/efm32/ext-device.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/../util/zigbee-framework/zigbee-device-common.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/../util/zigbee-framework/zigbee-device-library.c \
  ../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/cortexm3/efm32/bootloader-interface-app.c \
  ../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/cortexm3/efm32/bootloader-interface.c \
  ../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/plugin/serial/cortexm/efm32/com.c \
  ../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/bootloader/api/btl_interface.c \
  ../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/bootloader/api/btl_interface_storage.c \
  ../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/emdrv/uartdrv/src/uartdrv.c \
 \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/plugin/antenna-stub/antenna-stub.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/stack/framework/ccm-star.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/radio/rail_lib/plugin/coexistence/protocol/ieee802154/coexistence-802154.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/radio/rail_lib/plugin/coexistence/protocol/ieee802154/coulomb-counter-802154.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin/concentrator/concentrator-support.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin/concentrator/concentrator-support-cli.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin/counters/counters-cli.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin/counters/counters-ota.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin/counters/counters-soc.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/segger/systemview/SEGGER/SEGGER_RTT.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/plugin/debug-jtag/debug-jtag-efr32.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin/device-table/device-table.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin/device-table/device-table-cli.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin/device-table/device-table-discovery.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin/device-table/device-table-tracking.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/cortexm3/efm32/hal-config.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/cortexm3/efm32/hal-config-gpio.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/service/mpu/src/sl_mpu.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin-soc/idle-sleep/idle-sleep.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin-soc/idle-sleep/idle-sleep-cli.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin-soc/idle-sleep/idle-sleep-soc.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/aes_aes.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/crypto_aes.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/crypto_ble.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/crypto_ecp.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/crypto_management.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/crypto_sha.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/cryptoacc_aes.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/cryptoacc_ccm.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/cryptoacc_cmac.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/cryptoacc_ecp.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/cryptoacc_gcm.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/cryptoacc_management.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/cryptoacc_sha.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/cryptoacc_trng.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/entropy_adc.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/entropy_rail.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/radioaes.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/radioaes_aes.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/radioaes_ble.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/se_aes.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/se_ccm.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/se_cmac.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/se_ecp.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/se_gcm.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/se_jpake.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/se_management.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/se_sha.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/se_trng.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/shax.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/src/trng.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/aes.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/aesni.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/arc4.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/asn1parse.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/asn1write.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/base64.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/bignum.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/blowfish.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/camellia.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/ccm.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/certs.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/cipher.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/cipher_wrap.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/cmac.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/ctr_drbg.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/debug.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/des.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/dhm.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/ecdh.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/ecdsa.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/ecjpake.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/ecp.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/ecp_curves.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/entropy.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/entropy_poll.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/error.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/gcm.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/havege.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/hmac_drbg.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/md.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/md2.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/md4.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/md5.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/md_wrap.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/memory_buffer_alloc.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/net_sockets.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/oid.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/padlock.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/pem.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/pk.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/pk_wrap.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/pkcs11.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/pkcs12.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/pkcs5.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/pkparse.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/pkwrite.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/ripemd160.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/rsa.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/rsa_internal.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/sha1.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/sha256.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/sha512.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/ssl_cache.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/ssl_ciphersuites.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/ssl_cli.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/ssl_cookie.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/ssl_srv.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/ssl_ticket.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/ssl_tls.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/threading.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/timing.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/version.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/version_features.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/x509.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/x509_create.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/x509_crl.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/x509_crt.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/x509_csr.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/x509write_crt.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/x509write_csr.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/library/xtea.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin-soc/micrium-rtos/micrium-rtos-main.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin-soc/micrium-rtos/micrium-rtos-sleep.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin-soc/micrium-rtos/os_app_hooks.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/common/source/rtos/rtos_err_str.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/common/source/kal/kal_kernel.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/cpu/source/cpu_core.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/kernel/source/os_cfg_app.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/kernel/source/os_core.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/kernel/source/os_dbg.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/kernel/source/os_flag.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/kernel/source/os_mon.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/kernel/source/os_msg.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/kernel/source/os_mutex.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/kernel/source/os_prio.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/kernel/source/os_q.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/kernel/source/os_sem.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/kernel/source/os_stat.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/kernel/source/os_task.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/kernel/source/os_time.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/kernel/source/os_tmr.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/kernel/source/os_var.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/common/source/lib/lib_ascii.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/common/source/lib/lib_math.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/common/source/lib/lib_mem.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/common/source/lib/lib_str.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/ports/source/gnu/armv7m_cpu_c.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/ports/source/gnu/armv7m_cpu_a.S \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/ports/source/gnu/armv7m_os_cpu_c.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/ports/source/gnu/armv7m_os_cpu_a.S \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/bsp/siliconlabs/generic/source/bsp_cpu.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin/network-creator/network-creator.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin/network-creator/network-creator-cli.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin/network-creator-security/network-creator-security.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin/network-creator-security/network-creator-security-cli.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin/network-steering/network-steering.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin/network-steering/network-steering-cli.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin/network-steering/network-steering-v2.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin/network-steering/network-steering-soc.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/emdrv/nvm3/src/nvm3_lock.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/emdrv/nvm3/src/nvm3_default.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/emdrv/nvm3/src/nvm3_hal_flash.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin/scan-dispatch/scan-dispatch.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/plugin/serial/serial.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin/stack-diagnostics/stack-diagnostics.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/plugin/serial/ember-printf-wrapper.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/stack/framework/strong-random-api.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin/update-tc-link-key/update-tc-link-key.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin/update-tc-link-key/update-tc-link-key-cli.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/cli/core-cli.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/cli/network-cli.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/cli/option-cli.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/cli/plugin-cli.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/cli/security-cli.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/cli/zcl-cli.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/cli/zdo-cli.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/security/af-node.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/security/af-security-common.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/security/af-trust-center.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/security/crypto-state.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/util/af-event.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/util/af-main-common.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/util/attribute-size.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/util/attribute-storage.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/util/attribute-table.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/util/client-api.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/util/message.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/util/multi-network.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/util/print.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/util/print-formatter.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/util/process-cluster-message.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/util/process-global-message.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/util/service-discovery-common.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/util/time-util.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/util/util.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/util/af-main-soc.c \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/util/service-discovery-soc.c \
 \
Z3Aliyun1_callbacks.c \ \

LIB_FILES = \
 \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/build/binding-table-library-cortexm3-gcc-efr32mg12p-rail/binding-table-library.a \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/build/cbke-163k1-stub-library-cortexm3-gcc-efr32mg12p-rail/cbke-163k1-stub-library.a \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/build/cbke-283k1-stub-library-cortexm3-gcc-efr32mg12p-rail/cbke-283k1-stub-library.a \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/build/cbke-stub-library-cortexm3-gcc-efr32mg12p-rail/cbke-stub-library.a \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/build/cbke-library-dsa-sign-stub-cortexm3-gcc-efr32mg12p-rail/cbke-library-dsa-sign-stub.a \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/build/cbke-library-dsa-verify-stub-cortexm3-gcc-efr32mg12p-rail/cbke-library-dsa-verify-stub.a \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/build/cbke-library-dsa-verify-283k1-stub-cortexm3-gcc-efr32mg12p-rail/cbke-library-dsa-verify-283k1-stub.a \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/build/debug-basic-library-cortexm3-gcc-efr32mg12p-rail/debug-basic-library.a \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/build/debug-extended-stub-library-cortexm3-gcc-efr32mg12p-rail/debug-extended-stub-library.a \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/build/end-device-bind-stub-library-cortexm3-gcc-efr32mg12p-rail/end-device-bind-stub-library.a \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/build/gp-stub-library-cortexm3-gcc-efr32mg12p-rail/gp-stub-library.a \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/build/hal-library-cortexm3-gcc-efr32mg12p-rail/hal-library.a \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/build/install-code-library-stub-cortexm3-gcc-efr32mg12p-rail/install-code-library-stub.a \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/build/multi-network-stub-library-cortexm3-gcc-efr32mg12p-rail/multi-network-stub-library.a \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/emdrv/nvm3/lib/libnvm3_CM4_gcc.a \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/build/packet-validate-library-cortexm3-gcc-efr32mg12p-rail/packet-validate-library.a \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/radio/rail_lib/autogen/librail_release/librail_multiprotocol_efr32xg12_gcc_release.a \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/build/security-library-link-keys-stub-cortexm3-gcc-efr32mg12p-rail/security-library-link-keys-stub.a \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/build/sim-eeprom2-to-nvm3-upgrade-stub-library-cortexm3-gcc-efr32mg12p-rail/sim-eeprom2-to-nvm3-upgrade-stub-library.a \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/build/source-route-library-cortexm3-gcc-efr32mg12p-rail/source-route-library.a \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/build/zigbee-pro-stack-cortexm3-gcc-efr32mg12p-rail/zigbee-pro-stack.a \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/build/zigbee-r22-support-stub-library-cortexm3-gcc-efr32mg12p-rail/zigbee-r22-support-stub-library.a \
../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/build/zll-stub-library-cortexm3-gcc-efr32mg12p-rail/zll-stub-library.a \
 \
 \

CDEFS = -DAPP_GECKO_INFO_PAGE_BTL \
-DCORTEXM3 \
-DCORTEXM3_EFR32 \
-DCORTEXM3_EFR32_MICRO \
-DCORTEXM3_EFM32_MICRO \
-DEFR32_SERIES1_CONFIG2_MICRO \
-DEFR32MG12P \
-DEFR32MG12P332F1024GL125 \
-DATTRIBUTE_STORAGE_CONFIGURATION=\"Z3Aliyun1_endpoint_config.h\" \
-DCONFIGURATION_HEADER=\"app/framework/util/config.h\" \
-DGENERATED_TOKEN_HEADER=\"Z3Aliyun1_tokens.h\" \
-DPLATFORM_HEADER=\"platform/base/hal/micro/cortexm3/compiler/gcc.h\" \
-DZA_GENERATED_HEADER=\"Z3Aliyun1.h\" \
-DPSSTORE_SIZE=0 \
-DLONGTOKEN_SIZE=0 \
-DLOCKBITS_IN_MAINFLASH_SIZE=0 \
  -DHAL_CONFIG=1 \
  -DEMBER_AF_USE_HWCONF \
  -DNO_LED=1 \
  -DMBEDTLS_CIPHER_MODE_CBC=1 \
  -DMBEDTLS_CIPHER_MODE_CFB=1 \
  -DEMBER_AF_API_EMBER_TYPES=\"stack/include/ember-types.h\" \
  -DEMBER_AF_API_DEBUG_PRINT=\"app/framework/util/print.h\" \
  -DEMBER_AF_API_AF_HEADER=\"app/framework/include/af.h\" \
  -DEMBER_AF_API_AF_SECURITY_HEADER=\"app/framework/security/af-security.h\" \
  -DEMBER_AF_API_NEIGHBOR_HEADER=\"stack/include/stack-info.h\" \
  -DEMBER_STACK_ZIGBEE \
  -DMBEDTLS_CONFIG_FILE=\"mbedtls-config-generated.h\" \
  -DUSE_NVM3 \
  -DNVM3_DEFAULT_NVM_SIZE=NVM3_FLASH_PAGES*FLASH_PAGE_SIZE \
  -DEMLIB_USER_CONFIG \
  -DMICRIUMOS \
  -DAPPLICATION_TOKEN_HEADER=\"znet-token.h\" \
  -DAPPLICATION_MFG_TOKEN_HEADER=\"znet-mfg-token.h\" \
  -DMBEDTLS_DEVICE_ACCELERATION_CONFIG_FILE=\"configs/config-device-acceleration.h\" \
  -DMBEDTLS_DEVICE_ACCELERATION_CONFIG_APP_FILE=\"config-device-acceleration-app.h\" \
  -DNVM3_FLASH_PAGES=18 \
  -DNVM3_DEFAULT_CACHE_SIZE=254 \
  -DNVM3_MAX_OBJECT_SIZE=254 \
  -DNVM3_DEFAULT_REPACK_HEADROOM=0 \
  -DPHY_RAIL=1 \
  -DPHY_RAIL_MP=1 \
  -DMBEDTLS_DEVICE_ACCELERATION_CONFIG_FILE=\"configs/config-device-acceleration.h\" \
  -DMBEDTLS_DEVICE_ACCELERATION_CONFIG_APP_FILE=\"config-device-acceleration-app.h\" \
  -DNVM3_FLASH_PAGES=18 \
  -DNVM3_DEFAULT_CACHE_SIZE=254 \
  -DNVM3_MAX_OBJECT_SIZE=254 \
  -DNVM3_DEFAULT_REPACK_HEADROOM=0 \
  -DPHY_RAIL=1 \
  -DPHY_RAIL_MP=1 \
 \

ASMDEFS = -DAPP_GECKO_INFO_PAGE_BTL \
-DCORTEXM3 \
-DCORTEXM3_EFR32 \
-DCORTEXM3_EFR32_MICRO \
-DCORTEXM3_EFM32_MICRO \
-DEFR32_SERIES1_CONFIG2_MICRO \
-DEFR32MG12P \
-DEFR32MG12P332F1024GL125 \
-DATTRIBUTE_STORAGE_CONFIGURATION=\"Z3Aliyun1_endpoint_config.h\" \
-DCONFIGURATION_HEADER=\"app/framework/util/config.h\" \
-DGENERATED_TOKEN_HEADER=\"Z3Aliyun1_tokens.h\" \
-DPLATFORM_HEADER=\"platform/base/hal/micro/cortexm3/compiler/gcc.h\" \
-DZA_GENERATED_HEADER=\"Z3Aliyun1.h\" \
-DPSSTORE_SIZE=0 \
-DLONGTOKEN_SIZE=0 \
-DLOCKBITS_IN_MAINFLASH_SIZE=0 \
  -DHAL_CONFIG=1 \
  -DEMBER_AF_USE_HWCONF \
  -DNO_LED=1 \
  -DMBEDTLS_CIPHER_MODE_CBC=1 \
  -DMBEDTLS_CIPHER_MODE_CFB=1 \
  -DEMBER_AF_API_EMBER_TYPES=\"stack/include/ember-types.h\" \
  -DEMBER_AF_API_DEBUG_PRINT=\"app/framework/util/print.h\" \
  -DEMBER_AF_API_AF_HEADER=\"app/framework/include/af.h\" \
  -DEMBER_AF_API_AF_SECURITY_HEADER=\"app/framework/security/af-security.h\" \
  -DEMBER_AF_API_NEIGHBOR_HEADER=\"stack/include/stack-info.h\" \
  -DEMBER_STACK_ZIGBEE \
  -DMBEDTLS_CONFIG_FILE=\"mbedtls-config-generated.h\" \
  -DUSE_NVM3 \
  -DNVM3_DEFAULT_NVM_SIZE=NVM3_FLASH_PAGES*FLASH_PAGE_SIZE \
  -DEMLIB_USER_CONFIG \
  -DMICRIUMOS \
  -DAPPLICATION_TOKEN_HEADER=\"znet-token.h\" \
  -DAPPLICATION_MFG_TOKEN_HEADER=\"znet-mfg-token.h\" \
  -DMBEDTLS_DEVICE_ACCELERATION_CONFIG_FILE=\"configs/config-device-acceleration.h\" \
  -DMBEDTLS_DEVICE_ACCELERATION_CONFIG_APP_FILE=\"config-device-acceleration-app.h\" \
  -DNVM3_FLASH_PAGES=18 \
  -DNVM3_DEFAULT_CACHE_SIZE=254 \
  -DNVM3_MAX_OBJECT_SIZE=254 \
  -DNVM3_DEFAULT_REPACK_HEADROOM=0 \
  -DPHY_RAIL=1 \
  -DPHY_RAIL_MP=1 \
  -DMBEDTLS_DEVICE_ACCELERATION_CONFIG_FILE=\"configs/config-device-acceleration.h\" \
  -DMBEDTLS_DEVICE_ACCELERATION_CONFIG_APP_FILE=\"config-device-acceleration-app.h\" \
  -DNVM3_FLASH_PAGES=18 \
  -DNVM3_DEFAULT_CACHE_SIZE=254 \
  -DNVM3_MAX_OBJECT_SIZE=254 \
  -DNVM3_DEFAULT_REPACK_HEADROOM=0 \
  -DPHY_RAIL=1 \
  -DPHY_RAIL_MP=1 \
 \

CINC = -I./ \
-I$(ARM_IAR7_DIR)/ARM/INC \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7 \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/../.. \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/../../stack \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/../util \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/include \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/plugin \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/.. \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/cortexm3/efm32 \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/cortexm3/efm32/config \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/micro/cortexm3/efm32/efr32 \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../CMSIS/Include \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../Device/SiliconLabs/EFR32MG12P/Include \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emdrv/common/inc \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emdrv/config \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emdrv/dmadrv/inc \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emdrv/gpiointerrupt/inc \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../service/sleeptimer/inc \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../service/sleeptimer/config \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../common/inc \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emdrv/sleep/inc \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emdrv/spidrv/inc \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emdrv/tempdrv/inc \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emdrv/uartdrv/inc \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emdrv/ustimer/inc \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../emlib/inc \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../middleware/glib \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../middleware/glib/glib \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/base/hal/../../radio/rail_lib/plugin \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/halconfig/inc/hal-config \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/hardware/module/config \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/hardware/kit/common/halconfig \
-I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/hardware/kit/common/bsp \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/bootloader \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/common/inc \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/emdrv/nvm3/inc \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/bsp/siliconlabs/generic/include \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/common/include \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/micrium_os/kernel/include \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/radio/rail_lib/chip/efr32/efr32xg1x \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/radio/rail_lib/common \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/radio/rail_lib/plugin/coexistence/common \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/radio/rail_lib/plugin/coexistence/hal/efr32 \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/radio/rail_lib/plugin/coexistence/protocol/ieee802154 \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/radio/rail_lib/protocol/ble \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/radio/rail_lib/protocol/ieee802154 \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/radio/rail_lib/protocol/zwave \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/platform/service/mpu/inc \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/protocol/zigbee/app/framework/plugin-soc/micrium-rtos/config \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/plugin/plugin-common/mbedtls \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/include \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/include/mbedtls \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/mbedtls/sl_crypto/include \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/segger/systemview/Config \
  -I../../../../opt/SimplicityStudio_v4/developer/sdks/gecko_sdk_suite/v2.7/util/third_party/segger/systemview/SEGGER \
  -Ihal-config \
 \

TARGET = Z3Aliyun1

CSOURCES = $(filter %.c, $(SOURCE_FILES))
ASMSOURCES = $(filter %.s79, $(SOURCE_FILES))
ASMSOURCES2 = $(filter %.s, $(SOURCE_FILES))

COBJS = $(addprefix $(OUTPUT_DIR)/,$(CSOURCES:.c=.o))
ASMOBJS = $(addprefix $(OUTPUT_DIR)/,$(ASMSOURCES:.s79=.o))
ASMOBJS2 = $(addprefix $(OUTPUT_DIR)/,$(ASMSOURCES2:.s=.o))

OUTPUT_DIRS = $(sort $(dir $(COBJS)) $(dir $(ASMOBJS)) $(dir $(ASMOBJS2)))

ARCHITECTUREID = efr32~family[m]~series[1]~device_configuration[2]~performance[p]~radio[332]~flash[1024k]~temp[g]~package[l]~pins[125]~!module+brd4162a+gcc

# GNU ARM compiler
ifeq ($(findstring +gcc,$(ARCHITECTUREID)), +gcc)
$(info GCC Build)
	# Add linker circular reference as the order of objects may matter for any libraries used
	GROUP_START =-Wl,--start-group
	GROUP_END =-Wl,--end-group

	CCFLAGS = -g3 \
    -gdwarf-2 \
    -mcpu=cortex-m4 \
    -mthumb \
    -std=gnu99 \
    -Os  \
    -Wall  \
    -c  \
    -fmessage-length=0  \
    -ffunction-sections  \
    -fdata-sections  \
    -mfpu=fpv4-sp-d16  \
    -mfloat-abi=softfp \
	$(CDEFS) \
	$(CINC) \

	ASMFLAGS = -c \
	-g3 \
	-gdwarf-2 \
	-mcpu=cortex-m4 \
	-mthumb \
	-c \
	-x assembler-with-cpp \
	$(CINC) \
	$(ASMDEFS)

	LDFLAGS = -g3 \
	-gdwarf-2 \
	-mcpu=cortex-m4 \
	-mthumb -T "$(GLOBAL_BASE_DIR)/hal/micro/cortexm3/efm32/gcc-cfg.ld" \
	-L"$(GLOBAL_BASE_DIR)/hal/micro/cortexm3/" \
	-Xlinker --defsym="SIMEEPROM_SIZE=36864" \
	-Xlinker --defsym="PSSTORE_SIZE=0" \
	-Xlinker --defsym="LONGTOKEN_SIZE=0" \
	-Xlinker --defsym="LOCKBITS_IN_MAINFLASH_SIZE=0" \
	-Xlinker --defsym="FLASH_SIZE=1048576" \
	-Xlinker --defsym="RAM_SIZE=262144" \
	-Xlinker --defsym="FLASH_PAGE_SIZE=2048" \
	-Xlinker --defsym="APP_BTL=1" \
	-Xlinker --defsym="EMBER_MALLOC_HEAP_SIZE=0" \
	-Xlinker --defsym="HEADER_SIZE=512" \
	-Xlinker --defsym="BTL_SIZE=16384" \
	-Xlinker --gc-sections \
	-Xlinker -Map="$(PROJECTNAME).map" \
	-mfpu=fpv4-sp-d16 \
	-mfloat-abi=softfp --specs=nano.specs -u _printf_float \
	-Wl,--start-group -lgcc -lc -lnosys   -Wl,--end-group

	ARCHFLAGS = r

	ELFTOOLFLAGS_BIN = -O binary
	ELFTOOLFLAGS_HEX = -O ihex
	ELFTOOLFLAGS_S37 = -O srec

	ifeq ($(OS),Windows_NT)
		ARCH = $(ARM_GNU_DIR)/bin/arm-none-eabi-gcc-ar.exe
		AS = $(ARM_GNU_DIR)/bin/arm-none-eabi-gcc.exe
		CC = $(ARM_GNU_DIR)/bin/arm-none-eabi-gcc.exe
		ELFTOOL = $(ARM_GNU_DIR)/bin/arm-none-eabi-objcopy.exe
		LD = $(ARM_GNU_DIR)/bin/arm-none-eabi-gcc.exe
	else
		ARCH = $(ARM_GNU_DIR)/bin/arm-none-eabi-gcc-ar
		AS = $(ARM_GNU_DIR)/bin/arm-none-eabi-gcc
		CC = $(ARM_GNU_DIR)/bin/arm-none-eabi-gcc
		ELFTOOL = $(ARM_GNU_DIR)/bin/arm-none-eabi-objcopy
		LD = $(ARM_GNU_DIR)/bin/arm-none-eabi-gcc
	endif

endif

# IAR 7.xx toolchain
ifeq ($(findstring +iar,$(ARCHITECTUREID)), +iar)
$(info IAR Build)

	# IAR is not sensitive to linker lib order thus no groups needed.
	GROUP_START =
	GROUP_END =
	CINC += -I$(ARM_IAR6_DIR)/ARM/INC

	ifndef ARM_IAR7_DIR
	$(error ARM_IAR7_DIR is not set. Please define ARM_IAR7_DIR pointing to your IAR 7.xx installation folder.)
	endif

	CCFLAGS = --cpu=cortex-m3 \
	--cpu_mode=thumb \
	--diag_suppress=Pa050 \
	-e \
	--endian=little \
	--fpu=none \
	--no_path_in_file_macros \
	--separate_cluster_for_initialized_variables \
	--dlib_config=$(ARM_IAR7_DIR)/ARM/inc/c/DLib_Config_Normal.h \
	--debug \
	--dependencies=m $*.d \
	-Ohz \
	$(CDEFS) \
	$(CINC)

	ASMFLAGS = --cpu cortex-M3 \
	--fpu None \
	-s+ \
	"-M<>" \
	-w+ \
	-t2 \
	-r \
	$(CINC) \
	$(ASMDEFS)

	LDFLAGS = --entry __iar_program_start \
	--diag_suppress=Lp012 \
	--config $(GLOBAL_BASE_DIR)/hal/micro/cortexm3/efm32/iar-cfg.icf \
	--config_def APP_GECKO_INFO_PAGE_BTL=1 \
	--config_def EMBER_MALLOC_HEAP_SIZE=0

	ARCH = $(JAMEXE_PREFIX) $(ARM_IAR7_DIR)/arm/bin/iarchive.exe
	AS = $(JAMEXE_PREFIX) $(ARM_IAR7_DIR)/arm/bin/iasmarm.exe
	CC = $(JAMEXE_PREFIX) $(ARM_IAR7_DIR)/arm/bin/iccarm.exe
	ELFTOOL = $(JAMEXE_PREFIX) $(ARM_IAR7_DIR)/arm/bin/ielftool.exe
	LD = $(JAMEXE_PREFIX) $(ARM_IAR7_DIR)/arm/bin/ilinkarm.exe

	# No archiver arguments needed for IAR.
	ARCHFLAGS =

	ELFTOOLFLAGS_BIN = --bin
	ELFTOOLFLAGS_HEX = --ihex
	ELFTOOLFLAGS_S37 = --srec --srec-s3only

endif

.PHONY: all clean PROLOGUE

all: PROLOGUE $(OUTPUT_DIRS) $(COBJS) $(ASMOBJS) $(ASMOBJS2) $(LIB_FILES)
	@echo 'Linking...'
	@$(LD) $(GROUP_START) $(LDFLAGS) $(COBJS) $(ASMOBJS) $(ASMOBJS2) $(LIB_FILES) $(GROUP_END) -o $(OUTPUT_DIR)/$(TARGET).out
	@$(ELFTOOL) $(OUTPUT_DIR)/$(TARGET).out $(ELFTOOLFLAGS_BIN) $(OUTPUT_DIR)/$(TARGET).bin
	@$(ELFTOOL) $(OUTPUT_DIR)/$(TARGET).out $(ELFTOOLFLAGS_HEX) $(OUTPUT_DIR)/$(TARGET).hex
	@$(ELFTOOL) $(OUTPUT_DIR)/$(TARGET).out $(ELFTOOLFLAGS_S37) $(OUTPUT_DIR)/$(TARGET).s37
	@echo 'Done.'

PROLOGUE:
#	@echo $(COBJS)
#	@echo $(ASMOBJS)
#	@echo $(ASMOBJS2)

$(OUTPUT_DIRS):
	@mkdir -p $@

$(COBJS): %.o:
	@echo 'Building $(notdir $(@:%.o=%.c))...'
	@$(CC) $(CCFLAGS) -o $@ $(filter %$(@:$(OUTPUT_DIR)/%.o=%.c),$(CSOURCES)) > /dev/null \

$(ASMOBJS): %.o:
	@echo 'Building $(notdir $(@:%.o=%.s79))...'
	@$(AS) $(ASMFLAGS) -o $@ $(filter %$(@:$(OUTPUT_DIR)/%.o=%.s79),$(ASMSOURCES)) > /dev/null

$(ASMOBJS2): %.o:
	@echo 'Building $(notdir $(@:%.o=%.s))...'
	@$(AS) $(ASMFLAGS) -o $@ $(filter %$(@:$(OUTPUT_DIR)/%.o=%.s),$(ASMSOURCES2)) > /dev/null

clean:
	$(RM) -r $(COBJS)
	$(RM) -r $(ASMOBJS)
	$(RM) -r $(ASMOBJS2)
	$(RM) -r $(OUTPUT_DIR)
