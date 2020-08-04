
/**
 * NOTE:
 *
 * HAL_TCP_xxx API reference implementation: wrappers/os/ubuntu/HAL_TCP_linux.c
 *
 */
#include "infra_types.h"
#include "infra_defs.h"
#include "infra_compat.h"
#include "wrappers_defs.h"
#include "iot_import_awss.h"
#include "stdarg.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "app/framework/include/af.h"
#include "hal/micro/system-timer.h"
#include <kernel/include/os.h>
#include <common/include/rtos_prio.h>
#include "mbedtls/aes.h"
#include "wifi/wgm110.h"
#include "dbgprint.h"

#define AES_BLOCK_SIZE 16

#define MS_TO_TICK(ms) ((ms) * OS_CFG_TICK_RATE_HZ / 1000)

uint32_t g_heap_used = 0;


int HAL_Snprintf(char *str, const int len, const char *fmt, ...)
{
    va_list args;
    int     rc;

    va_start(args, fmt);
    rc = vsnprintf(str, len, fmt, args);
    va_end(args);

    return rc;
}

int HAL_Vsnprintf(char *str, const int len, const char *format, va_list ap)
{
    return vsnprintf(str, len, format, ap);
}

void HAL_Printf(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}


/**
 * @brief Allocates a block of size bytes of memory, returning a pointer to the beginning of the block.
 *
 * @param [in] size @n specify block size in bytes.
 * @return A pointer to the beginning of the block.
 * @see None.
 * @note Block value is indeterminate.
 */
void *HAL_Malloc(uint32_t size)
{
    uint8_t *pdata = (uint8_t *)malloc(size + 8);
    if (NULL == pdata) {
        dbg_error("not enough mem");
        return NULL;
    }

    *(uint8_t *)pdata = '&';
    *(uint8_t *)(pdata + 1) = '$';
    *(uint8_t *)(pdata + 2) = '#';
    *(uint8_t *)(pdata + 3) = '!';
    *(uint32_t *)(pdata + 4) = size;
    g_heap_used += size + 4;
    //dbg_trace("heap used 0x%lx bytes", g_heap_used);
    return pdata + 8;
}

/**
 * @brief Deallocate memory block
 *
 * @param[in] ptr @n Pointer to a memory block previously allocated with platform_malloc.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_Free(void *ptr)
{
    uint8_t *pdata = (uint8_t *)ptr;
    
    if (NULL == ptr) {
        return;
    }

    if (('&' != *(uint8_t *)(pdata - 8))
        || ('$' != *(uint8_t *)(pdata - 7))
        || ('#' != *(uint8_t *)(pdata - 6))
        || ('!' != *(uint8_t *)(pdata - 5))) {
        dbg_error("freed an invalid mem");
        return;
    }

    g_heap_used -= *(uint32_t *)(pdata - 4) + 4;
    //dbg_trace("heap used 0x%lx bytes", g_heap_used);
    free(pdata - 8);
}

void HAL_Reboot(void)
{
    while (1) {
        halReboot();
    }
}

uint32_t HAL_Random(uint32_t region)
{
    return (region > 0) ? (halCommonGetRandom() % region) : 0;
}


void HAL_Srandom(uint32_t seed)
{
	halStackSeedRandom(seed);
}

/**
 * @brief Sleep thread itself.
 *
 * @param [in] ms @n the time interval for which execution is to be suspended, in milliseconds.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_SleepMs(uint32_t ms)
{
	RTOS_ERR err;

    halResetWatchdog();
    
    if (0 == ms) {
        return;
    } else if (10000 < ms) {
        dbg_error("super long delay=%ld ms", ms);
        ms = 30000;
    }

	OSTimeDly(MS_TO_TICK(ms), OS_OPT_TIME_DLY, &err);
}


/**
 * @brief Retrieves the number of milliseconds that have elapsed since the system was boot.
 *
 * @return the number of milliseconds.
 * @see None.
 * @note None.
 */
uint64_t HAL_UptimeMs(void)
{
	return halCommonGetInt64uMillisecondTick();
}
static volatile uint8_t g_kvlist_mutex = 1;

int HAL_Kv_Set(const char *key, const void *val, int len, int sync)
{
    int        ret = 0;
    uint8_t    i;
    tokTypeKvs data;
    
    (void)sync;
    (void)len;

    if (sizeof(data.kv_key) <= strlen(key) || sizeof(data.value) < len) {
        dbg_error("key or value too long");
        dbg_error("key=%s", key);
        dbg_error("len=%d", len);
    }

    while (!g_kvlist_mutex) {
        HAL_SleepMs(1);
    }
    g_kvlist_mutex = 0;

    //lookup
    for (i = 0; i < MAX_KV_NUMBER; i++) {
        memset(&data, 0, sizeof(data));
        halCommonGetIndexedToken(&data, TOKEN_KV_PAIRS, i);
        if ('\0' == data.kv_key[0]) {
            continue;
        } else if (0 == strcmp(data.kv_key, key)) {
            break;
        }
    }

    if (i < MAX_KV_NUMBER) {
        data.value_len = len;
        memcpy(data.value, val, len);
    } else {
        //add
        for (i = 0; i < MAX_KV_NUMBER; i++) {
            memset(&data, 0, sizeof(data));
            halCommonGetIndexedToken(&data, TOKEN_KV_PAIRS, i);
            if ('\0' == data.kv_key[0]) {
                sprintf(data.kv_key, "%s", key);
                data.value_len = len;
                memcpy(data.value, val, len);
                break;
            }
        }    
    }

    if (i < MAX_KV_NUMBER) {
        halCommonSetIndexedToken(TOKEN_KV_PAIRS, i, &data);
    } else {
        ret = -1;
        dbg_error("not enough kv tokens");
        dbg_error("key=%s", key);
        dbg_error("len=%d", len);
    }

    g_kvlist_mutex = 1;
    return ret;
}

int HAL_Kv_Get(const char *key, void *buffer, int *buffer_len)
{
    int        ret = 0;
    uint8_t    i;
    tokTypeKvs data;

    while (!g_kvlist_mutex) {
        HAL_SleepMs(1);
    }
    g_kvlist_mutex = 0;
    
    //lookup
    for (i = 0; i < MAX_KV_NUMBER; i++) {
        memset(&data, 0, sizeof(data));
        halCommonGetIndexedToken(&data, TOKEN_KV_PAIRS, i);
        if ('\0' == data.kv_key[0]) {
            continue;
        } else if (0 == strcmp(data.kv_key, key)) {
            break;
        }
    }

    if (i < MAX_KV_NUMBER) {
        if (data.value_len > *buffer_len) {
            ret = -1;
            dbg_error("key or value too long");
            dbg_error("key=%s", key);
            dbg_error("len=%d", data.value_len);
        } else {
            *buffer_len = data.value_len;
            memcpy(buffer, data.value, data.value_len);
        }
    } else {
        ret = -1;   
    }

    g_kvlist_mutex = 1;
    return ret;

}

int HAL_Kv_Del(const char *key)
{
    int        ret = 0;
    uint8_t    i;
    tokTypeKvs data;
    
    while (!g_kvlist_mutex) {
        HAL_SleepMs(1);
    }
    g_kvlist_mutex = 0;

    //lookup
    for (i = 0; i < MAX_KV_NUMBER; i++) {
        memset(&data, 0, sizeof(data));
        halCommonGetIndexedToken(&data, TOKEN_KV_PAIRS, i);
        if ('\0' == data.kv_key[0]) {
            continue;
        } else if (0 == strcmp(data.kv_key, key)) {
            data.kv_key[0] = '\0';
            halCommonSetIndexedToken(TOKEN_KV_PAIRS, i, &data);
            break;
        }
    }

    g_kvlist_mutex = 1;
    return ret;
}

int HAL_Awss_Open_Ap(const char *ssid, const char *passwd, int beacon_interval, int hide)
{
    return wifi_start_ap((char *)ssid, (char *)passwd, (uint8_t)hide);
}

int HAL_Awss_Close_Ap()
{
    return wifi_stop_ap();
}

int HAL_Wifi_Get_Ap_Info(
            _OU_ char ssid[HAL_MAX_SSID_LEN],
            _OU_ char passwd[HAL_MAX_PASSWD_LEN],
            _OU_ uint8_t bssid[ETH_ALEN])
{
    dbg_trace("called");
    return 0;
}

int HAL_Awss_Connect_Ap(
            _IN_ uint32_t connection_timeout_ms,
            _IN_ char ssid[HAL_MAX_SSID_LEN],
            _IN_ char passwd[HAL_MAX_PASSWD_LEN],
            _IN_OPT_ enum AWSS_AUTH_TYPE auth,
            _IN_OPT_ enum AWSS_ENC_TYPE encry,
            _IN_OPT_ uint8_t bssid[ETH_ALEN],
            _IN_OPT_ uint8_t channel)
{
    tokTypeWiFiInfo data;
    memset(&data, 0, sizeof(data));
    memcpy(data.ssid, ssid, 63);
    memcpy(data.passwd, passwd, 63);
    halCommonSetToken(TOKEN_WIFI_INFO, &data);

    //HAL_Reboot();
    return wifi_connect(ssid, passwd);
}

int HAL_SetProductKey(char *product_key)
{
    dbg_error("traced");
    return 0;
}

int HAL_SetProductSecret(char *product_secret)
{
    dbg_error("traced");
    return 0;
}

int HAL_SetDeviceName(char *device_name)
{
    dbg_error("traced");
    return 0;
}

/**
 * @brief Get device name from user's system persistent storage
 *
 * @param [ou] device_name: array to store device name, max length is IOTX_DEVICE_NAME_LEN
 * @return the actual length of device name
 */
int HAL_GetDeviceName(char device_name[IOTX_DEVICE_NAME_LEN + 1])
{
    #if  1
    EmberEUI64 eui64;
    emberAfGetEui64(eui64);
    snprintf(device_name, IOTX_DEVICE_NAME_LEN, "%02X%02X%02X%02X%02X%02X%02X%02X", eui64[7],
                                                                                    eui64[6],
                                                                                    eui64[5],
                                                                                    eui64[4],
                                                                                    eui64[3],
                                                                                    eui64[2],
                                                                                    eui64[1],
                                                                                    eui64[0]);
    #else
    snprintf(device_name, IOTX_DEVICE_NAME_LEN, "000B57FFFEA8EF42");
    #endif /* #if 0 */
    return strlen(device_name);
}


/**
 * @brief Get device secret from user's system persistent storage
 *
 * @param [ou] device_secret: array to store device secret, max length is IOTX_DEVICE_SECRET_LEN
 * @return the actual length of device secret
 */
int HAL_GetDeviceSecret(char device_secret[IOTX_DEVICE_SECRET_LEN + 1])
{
    #if  1
    char device_name[IOTX_DEVICE_NAME_LEN + 1] = {0};
    char kv_key[63] = {0};
    int  bufflen = IOTX_DEVICE_SECRET_LEN + 1;

    HAL_GetDeviceName(device_name);
    snprintf(kv_key, sizeof(kv_key), "DYNAMIC_REG_%s", device_name);
    
    if (0 != HAL_Kv_Get(kv_key, device_secret, &bufflen)) {
        device_secret[0] = '\0';
    }
    #else
    snprintf(device_secret, IOTX_DEVICE_SECRET_LEN, "HTpj540oJsW6YrVxgFLp5y20XJRsuL1X");
    #endif /* #if 0 */
    
    return strlen(device_secret);
}

int HAL_SetDeviceSecret(char *device_secret)
{
    #if  1
    char device_name[IOTX_DEVICE_NAME_LEN + 1] = {0};
    char kv_key[63] = {0};

    if (0 == strlen(device_secret)) {
        return 0;
    }

    dbg_error("traced device_secret=%s", device_secret);

    HAL_GetDeviceName(device_name);
    snprintf(kv_key, sizeof(kv_key), "DYNAMIC_REG_%s", device_name);
    return HAL_Kv_Set(kv_key, device_secret, strlen(device_secret)+1, 0);
    #endif /* #if 0 */
    return 0;
}

/**
 * @brief Get firmware version
 *
 * @param [ou] version: array to store firmware version, max length is IOTX_FIRMWARE_VER_LEN
 * @return the actual length of firmware version
 */
int HAL_GetFirmwareVersion(char *version)
{
    sprintf(version, "fw-0.0.1");
    return strlen(version);
}


/**
 * @brief Get product key from user's system persistent storage
 *
 * @param [ou] product_key: array to store product key, max length is IOTX_PRODUCT_KEY_LEN
 * @return  the actual length of product key
 */
int HAL_GetProductKey(char product_key[IOTX_PRODUCT_KEY_LEN + 1])
{
    snprintf(product_key, IOTX_PRODUCT_KEY_LEN, "%s", "a1h5gKPj2DC");
    return strlen(product_key);
}


int HAL_GetProductSecret(char product_secret[IOTX_PRODUCT_SECRET_LEN + 1])
{
    snprintf(product_secret, IOTX_PRODUCT_SECRET_LEN, "%s", "Cd6woPQPuI67K9Je");
    return strlen(product_secret);
}


/**
 * @brief Create a mutex.
 *
 * @retval NULL : Initialize mutex failed.
 * @retval NOT_NULL : The mutex handle.
 * @see None.
 * @note None.
 */
void *HAL_MutexCreate(void)
{
	RTOS_ERR  err;
	char      name[16];
	OS_MUTEX *pmutex = NULL;
    //printf("[%s][%d]**** hal stub called **** \r\n", __func__, __LINE__);
	pmutex = (OS_MUTEX *)HAL_Malloc(sizeof(OS_MUTEX));
	if (NULL == pmutex) {
        dbg_error("malloc failed");
		return NULL;
	}

	sprintf(name, "mutex%lx", (uint32_t)pmutex);
	OSMutexCreate(pmutex, name, &err);
	if (RTOS_ERR_CODE_GET(err) != RTOS_ERR_NONE) {
        HAL_Free(pmutex);
        dbg_error("create mutex failed");
		return NULL;
	}
    
	return pmutex;
}


/**
 * @brief Destroy the specified mutex object, it will release related resource.
 *
 * @param [in] mutex @n The specified mutex.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_MutexDestroy(void *mutex)
{
	RTOS_ERR  err;
    (void)OSMutexDel(mutex,
                     OS_OPT_DEL_ALWAYS,
                     &err);
    HAL_Free(mutex);
}


/**
 * @brief Waits until the specified mutex is in the signaled state.
 *
 * @param [in] mutex @n the specified mutex.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_MutexLock(void *mutex)
{
	RTOS_ERR  err;
    OSMutexPend(mutex,
                0,
				OS_OPT_PEND_BLOCKING,
                DEF_NULL,
                &err);
	if (RTOS_ERR_CODE_GET(err) != RTOS_ERR_NONE) {
        dbg_error(" failed");
        return;
	}
}


/**
 * @brief Releases ownership of the specified mutex object..
 *
 * @param [in] mutex @n the specified mutex.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_MutexUnlock(void *mutex)
{
	RTOS_ERR  err;
    //printf("[%s][%d]**** hal stub called **** \r\n", __func__, __LINE__);
	OSMutexPost(mutex,
				OS_OPT_POST_NONE,
                &err);
	if (RTOS_ERR_CODE_GET(err) != RTOS_ERR_NONE) {
        dbg_error(" failed");
        return;
	}
}

typedef struct {
    mbedtls_aes_context ctx;
    uint8_t iv[16];
    uint8_t key[16];
} platform_aes_t;

p_HAL_Aes128_t HAL_Aes128_Init(
            _IN_ const uint8_t *key,
            _IN_ const uint8_t *iv,
            _IN_ AES_DIR_t dir)
{
    int ret = 0;
    platform_aes_t *p_aes128 = NULL;

    if (!key || !iv) return p_aes128;

    p_aes128 = (platform_aes_t *)calloc(1, sizeof(platform_aes_t));
    if (!p_aes128) return p_aes128;

    mbedtls_aes_init(&p_aes128->ctx);

    if (dir == HAL_AES_ENCRYPTION) {
        ret = mbedtls_aes_setkey_enc(&p_aes128->ctx, key, 128);
    } else {
        ret = mbedtls_aes_setkey_dec(&p_aes128->ctx, key, 128);
    }

    if (ret == 0) {
        memcpy(p_aes128->iv, iv, 16);
        memcpy(p_aes128->key, key, 16);
    } else {
        free(p_aes128);
        p_aes128 = NULL;
    }

    return (p_HAL_Aes128_t *)p_aes128;
}

int HAL_Aes128_Destroy(_IN_ p_HAL_Aes128_t aes)
{
    if (!aes) return -1;

    mbedtls_aes_free(&((platform_aes_t *)aes)->ctx);
    free(aes);

    return 0;
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
int HAL_Aes128_Cbc_Encrypt(
            _IN_ p_HAL_Aes128_t aes,
            _IN_ const void *src,
            _IN_ size_t blockNum,
            _OU_ void *dst)
{
    int i   = 0;
    int ret = -1;
    platform_aes_t *p_aes128 = (platform_aes_t *)aes;

    if (!aes || !src || !dst) return -1;

    for (i = 0; i < blockNum; ++i) {
        ret = mbedtls_aes_crypt_cbc(&p_aes128->ctx, MBEDTLS_AES_ENCRYPT, AES_BLOCK_SIZE,
                                    p_aes128->iv, src, dst);
        src = (uint8_t *)src + 16;
        dst = (uint8_t *)dst + 16;
    }

    return ret;
}

int HAL_Aes128_Cbc_Decrypt(
            _IN_ p_HAL_Aes128_t aes,
            _IN_ const void *src,
            _IN_ size_t blockNum,
            _OU_ void *dst)
{
    int i   = 0;
    int ret = -1;
    platform_aes_t *p_aes128 = (platform_aes_t *)aes;

    if (!aes || !src || !dst) return ret;

    for (i = 0; i < blockNum; ++i) {
        ret = mbedtls_aes_crypt_cbc(&p_aes128->ctx, MBEDTLS_AES_DECRYPT, AES_BLOCK_SIZE,
                                    p_aes128->iv, src, dst);
        src = (uint8_t *)src + 16;
        dst = (uint8_t *)dst + 16;
    }

    return ret;
}
#endif

#if defined(MBEDTLS_CIPHER_MODE_CFB)
int HAL_Aes128_Cfb_Encrypt(
            _IN_ p_HAL_Aes128_t aes,
            _IN_ const void *src,
            _IN_ size_t length,
            _OU_ void *dst)
{
    size_t offset = 0;
    int ret = -1;
    platform_aes_t *p_aes128 = (platform_aes_t *)aes;

    if (!aes || !src || !dst) return ret;

    ret = mbedtls_aes_crypt_cfb128(&p_aes128->ctx, MBEDTLS_AES_ENCRYPT, length,
                                   &offset, p_aes128->iv, src, dst);
    return ret;
}

int HAL_Aes128_Cfb_Decrypt(
            _IN_ p_HAL_Aes128_t aes,
            _IN_ const void *src,
            _IN_ size_t length,
            _OU_ void *dst)
{
    size_t offset = 0;
    int ret = -1;
    platform_aes_t *p_aes128 = (platform_aes_t *)aes;

    if (!aes || !src || !dst) return ret;

    ret = mbedtls_aes_setkey_enc(&p_aes128->ctx, p_aes128->key, 128);
    ret = mbedtls_aes_crypt_cfb128(&p_aes128->ctx, MBEDTLS_AES_DECRYPT, length,
                                   &offset, p_aes128->iv, src, dst);
    return ret;
}
#endif

typedef struct
{
	OS_TCB         		 tcb;
	void                *pstack;
}HalTaskHandle_S;

HalTaskHandle_S *HAL_MallocTaskHandle(int stacksize)
{
    HalTaskHandle_S *phd = HAL_Malloc(stacksize + sizeof(HalTaskHandle_S));
    if (NULL == phd) {
        dbg_error("not enough mem");
        return NULL;
    }

    phd->pstack = (void *)(phd + 1);
    return phd;
}

void HAL_FreeTaskHandle(HalTaskHandle_S *phd)
{
    HAL_Free(phd);
}

int HAL_ThreadCreate(
            _OU_ void **thread_handle,
            _IN_ void *(*work_routine)(void *),
            _IN_ void *arg,
            _IN_ hal_os_thread_param_t *hal_os_thread_param,
            _OU_ int *stack_used)
{
    RTOS_ERR  err;
    int       stacksize = 4096;
    int       taskpri = 7;
    CPU_CHAR *taskname = "app";
    HalTaskHandle_S *phd = NULL;
    
    if (stack_used) {
        *stack_used = 0;
    }
        
    if (NULL != hal_os_thread_param) {
        taskname = (CPU_CHAR *)hal_os_thread_param->name;
    	stacksize = hal_os_thread_param->stack_size;
        taskpri = hal_os_thread_param->priority % 16 + 7;
    }

    stacksize += 0x3FF;
    stacksize &= 0xFFFFFC00;
    if (stacksize < 4096) {
        stacksize = 4096;
    }

    phd = HAL_MallocTaskHandle(stacksize);
    if (NULL == phd) {
        dbg_error("failed");
        return -1;
    }

    if (stack_used) {
        *stack_used = 0;
    }

    OSTaskCreate((OS_TCB *)&(phd->tcb),
    			 taskname,
				 (OS_TASK_PTR)work_routine,
				 arg,
				 taskpri,
				 phd->pstack,
				 (stacksize / sizeof(CPU_STK)) / 32,
				 (stacksize / sizeof(CPU_STK)),
                 0, // Not receiving messages
                 0, // Default time quanta
                 NULL, // No TCB extensions
                 OS_OPT_TASK_STK_CLR | OS_OPT_TASK_STK_CHK,
                 &err);
    if (RTOS_ERR_CODE_GET(err) != RTOS_ERR_NONE) {
        dbg_error("failed");
        HAL_Free(phd);
        return -1;
    }
    *thread_handle = phd;
    return 0;
}

void HAL_ThreadDelete(_IN_ void *thread_handle)
{
	RTOS_ERR err;
    HalTaskHandle_S *phd = (HalTaskHandle_S *)thread_handle;

	if (NULL == thread_handle) {
        dbg_error("failed");
        return;
	}
    
	OSTaskDel(&(phd->tcb), &err);
    HAL_FreeTaskHandle(phd);
}

void *HAL_SemaphoreCreate(void)
{
	RTOS_ERR err;
	char     name[16];

	OS_SEM *sem = (OS_SEM *)HAL_Malloc(sizeof(OS_SEM));
    if (NULL == sem) {
        dbg_error("not enough mem");
        return NULL;
    }

    sprintf(name, "sem%lx", (uint32_t)sem);
    OSSemCreate(sem, name, 0, &err);

    return sem;
}

void HAL_SemaphoreDestroy(_IN_ void *sem)
{
	RTOS_ERR err;
	(void)OSSemDel(sem, OS_OPT_DEL_ALWAYS, &err);
	HAL_Free(sem);
    return;
}

void HAL_SemaphorePost(_IN_ void *sem)
{
	RTOS_ERR err;
	OSSemPost(sem, OS_OPT_POST_ALL, &err);
}

int HAL_SemaphoreWait(_IN_ void *sem, _IN_ uint32_t timeout_ms)
{
	RTOS_ERR err;
    //printf("[%s][%d]**** hal stub called **** \r\n", __func__, __LINE__);
	OSSemPend(sem, MS_TO_TICK(timeout_ms), OS_OPT_PEND_BLOCKING, NULL, &err);

	if (RTOS_ERR_CODE_GET(err) != RTOS_ERR_NONE) {
        dbg_error("failed");
		return -1;
	} else {
		return 0;
	}
}

typedef struct
{
	uint8_t              used;
    uint8_t              running;
    uint32_t             leftms;
    uint32_t             interval;
	timer_callback       callback;
	void				*callback_arg;
}HalTmrHandle_S;

static HalTmrHandle_S  g_hal_timer_array[16];
static void *          g_timer_taskid = NULL;
static void *          g_timer_mutex = NULL;

void *HAL_Timer_Task(void *para)
{
    uint64_t  lasttick = HAL_UptimeMs();

    (void)para;

    while(1) {
        uint8_t i;

        //update left
        uint64_t passed = HAL_UptimeMs() - lasttick;
        for (i = 0; i < 16; i++) {
            if (true != g_hal_timer_array[i].used
                || true != g_hal_timer_array[i].running) {
                continue;
            }

            HAL_MutexLock(g_timer_mutex);
            if (g_hal_timer_array[i].leftms <= passed) {
                g_hal_timer_array[i].leftms = 0;
            } else {
                g_hal_timer_array[i].leftms -= passed;
            }
            HAL_MutexUnlock(g_timer_mutex);

            if (0 == g_hal_timer_array[i].leftms) {
                HAL_MutexLock(g_timer_mutex);
                g_hal_timer_array[i].leftms = g_hal_timer_array[i].interval;
                g_hal_timer_array[i].running = false;
                HAL_MutexUnlock(g_timer_mutex);
                
                if (NULL != g_hal_timer_array[i].callback) {
                    g_hal_timer_array[i].callback(g_hal_timer_array[i].callback_arg);
                }
            }
        }

        lasttick += passed;
        HAL_SleepMs(10);
    }
}

int HAL_Timer_Task_Init()
{
    int                     ret;
    hal_os_thread_param_t   param;
    
    
    memset((void *)g_hal_timer_array, 0, sizeof(g_hal_timer_array));

    g_timer_mutex = HAL_MutexCreate();
    if (NULL == g_timer_mutex) { 
        dbg_error("failed");
        return WLAN_ERR_OS;
    }

    memset(&param, 0, sizeof(param));
    param.priority = 7;
    param.stack_size = 4096;
    param.name = "wrap_timer";
    
    ret = HAL_ThreadCreate(&g_timer_taskid,
                           HAL_Timer_Task,
                           NULL,
                           &param,
                           NULL);
    if (0 != ret) {
        dbg_error("failed");
        HAL_MutexDestroy(g_timer_mutex);
        return ret;
    }

    return 0;
}

void *HAL_Timer_Create(const char *name, timer_callback func, void *user_data)
{
    uint8_t i;

    (void)name;

    for (i = 0; i < 16; i++) {
        if (true != g_hal_timer_array[i].used) {
            HAL_MutexLock(g_timer_mutex);
            memset(&g_hal_timer_array[i], 0, sizeof(HalTmrHandle_S));
            g_hal_timer_array[i].callback = func;
            g_hal_timer_array[i].callback_arg = user_data;
            g_hal_timer_array[i].running = false;
            g_hal_timer_array[i].used = true;
            HAL_MutexUnlock(g_timer_mutex);            
            return &g_hal_timer_array[i];
        }
    }

    dbg_error("failed");
    return NULL;
}

int HAL_Timer_Start(void *timer, int ms)
{
    HalTmrHandle_S  *ptimer = (HalTmrHandle_S *)timer;

    HAL_MutexLock(g_timer_mutex);
    ptimer->interval = ms;
    ptimer->leftms = ms;
    ptimer->running = true;
    HAL_MutexUnlock(g_timer_mutex); 
    
    return 0;
}

int HAL_Timer_Stop(void *timer)
{
    HalTmrHandle_S  *ptimer = (HalTmrHandle_S *)timer;

    HAL_MutexLock(g_timer_mutex);
    ptimer->running = false;
    HAL_MutexUnlock(g_timer_mutex); 
    
    return 0;
}

int HAL_Timer_Delete(void *timer)
{
    HalTmrHandle_S  *ptimer = (HalTmrHandle_S *)timer;

    HAL_MutexLock(g_timer_mutex);
    ptimer->used = false;
    HAL_MutexUnlock(g_timer_mutex); 
    
    return 0;
}

char *HAL_Wifi_Get_Mac(_OU_ char mac_str[HAL_MAC_LEN])
{
    uint8_t mac[6] = {0};
    wifi_get_local_mac(mac);
    snprintf(mac_str, HAL_MAC_LEN, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return mac_str;
}

void HAL_IP2Str(int ipaddr, char *str)
{
    sprintf(str, "%d.%d.%d.%d", ipaddr & 0xFF, 
                                   (ipaddr >> 8) & 0xFF,
                                   (ipaddr >> 16) & 0xFF,
                                   (ipaddr >> 24) & 0xFF);
}

uint32_t HAL_Wifi_Get_IP(_OU_ char ip_str[NETWORK_ADDR_LEN], _IN_ const char *ifname)
{
    uint32_t ipaddr = wifi_get_local_ipaddr();
    HAL_IP2Str(ipaddr, ip_str);
    return ipaddr;
}

/**
 * @brief Destroy the specific TCP connection.
 *
 * @param [in] fd: @n Specify the TCP connection by handle.
 *
 * @return The result of destroy TCP connection.
 * @retval < 0 : Fail.
 * @retval   0 : Success.
 */
int HAL_TCP_Destroy(uintptr_t fd)
{
    if (0 != wifi_tcpip_tcp_close((uint8_t)fd)) {
        dbg_error("failed");
        return -1;
    }

    return 0;
}

int32_t HAL_SSL_Destroy(uintptr_t handle)
{
    if (0 != wifi_tcpip_tcp_close((uint8_t)handle)) {
        dbg_error("failed");
    }

    return 0;
}


uintptr_t HAL_SSL_Establish(const char *host, uint16_t port, const char *ca_crt, uint32_t ca_crt_len)
{
    uint8_t endpoint;

    dbg_trace("host=[%s] port=[%d]", host, port);

    if (NULL != ca_crt) {
        if (0 != wifi_tls_set_user_cert(ca_crt)) {
            dbg_error("failed");
            return (uintptr_t)-1;
        }
    }
    
    if (0 != wifi_tcpip_tls_connect_byhostname(host, port, &endpoint)) {
        dbg_error("failed");
        return (uintptr_t)-1;
    }

    return (uintptr_t)endpoint;
}


int HAL_SSL_Read(uintptr_t handle, char *buf, int len, int timeout_ms)
{
    return wifi_tcpip_read((uint8_t)handle, (uint8_t *)buf, (int)len, (int)timeout_ms);
}


int HAL_SSL_Write(uintptr_t handle, const char *buf, int len, int timeout_ms)
{
    return wifi_tcpip_write((uint8_t)handle, (uint8_t *)buf, (int)len, (int)timeout_ms);
}

/**
 * @brief Establish a TCP connection.
 *
 * @param [in] host: @n Specify the hostname(IP) of the TCP server
 * @param [in] port: @n Specify the TCP port of TCP server
 *
 * @return The handle of TCP connection.
   @retval   0 : Fail.
   @retval > 0 : Success, the value is handle of this TCP connection.
 */
uintptr_t HAL_TCP_Establish(const char *host, uint16_t port)
{
    uint8_t endpoint;

    if (0 != wifi_tcpip_tcp_connect_byhostname(host, port, &endpoint)) {
        dbg_error("failed");
        return (uintptr_t)-1;
    }

    return (uintptr_t)endpoint;
}


/**
 * @brief Read data from the specific TCP connection with timeout parameter.
 *        The API will return immediately if 'len' be received from the specific TCP connection.
 *
 * @param [in] fd @n A descriptor identifying a TCP connection.
 * @param [out] buf @n A pointer to a buffer to receive incoming data.
 * @param [out] len @n The length, in bytes, of the data pointed to by the 'buf' parameter.
 * @param [in] timeout_ms @n Specify the timeout value in millisecond. In other words, the API block 'timeout_ms' millisecond maximumly.
 *
 * @retval       -2 : TCP connection error occur.
 * @retval       -1 : TCP connection be closed by remote server.
 * @retval        0 : No any data be received in 'timeout_ms' timeout period.
 * @retval (0, len] : The total number of bytes be received in 'timeout_ms' timeout period.

 * @see None.
 */
int32_t HAL_TCP_Read(uintptr_t fd, char *buf, uint32_t len, uint32_t timeout_ms)
{
    return wifi_tcpip_read((uint8_t)fd, (uint8_t *)buf, (int)len, (int)timeout_ms);
}


/**
 * @brief Write data into the specific TCP connection.
 *        The API will return immediately if 'len' be written into the specific TCP connection.
 *
 * @param [in] fd @n A descriptor identifying a connection.
 * @param [in] buf @n A pointer to a buffer containing the data to be transmitted.
 * @param [in] len @n The length, in bytes, of the data pointed to by the 'buf' parameter.
 * @param [in] timeout_ms @n Specify the timeout value in millisecond. In other words, the API block 'timeout_ms' millisecond maximumly.
 *
 * @retval      < 0 : TCP connection error occur..
 * @retval        0 : No any data be write into the TCP connection in 'timeout_ms' timeout period.
 * @retval (0, len] : The total number of bytes be written in 'timeout_ms' timeout period.

 * @see None.
 */
int32_t HAL_TCP_Write(uintptr_t fd, const char *buf, uint32_t len, uint32_t timeout_ms)
{
    return wifi_tcpip_write((uint8_t)fd, (uint8_t *)buf, (int)len, (int)timeout_ms);
}

intptr_t HAL_UDP_create_without_connect(_IN_ const char *host, _IN_ unsigned short port)
{
    uint8_t endpoint = 255;

    (void)host;
    if (0 != wifi_udp_listen(port, &endpoint)) {
        dbg_error("failed");
        return (intptr_t)-1;
    }
    
    return (intptr_t)endpoint;
}

int HAL_UDP_joinmulticast(_IN_ intptr_t sockfd,
                          _IN_ char *p_group)
{
	int      ipaddr;
    int      auipaddr[4];

    sscanf(p_group, "%d.%d.%d.%d", &auipaddr[0], &auipaddr[1], &auipaddr[2], &auipaddr[3]);
    ipaddr = (auipaddr[0] & 0xFF) |  ((auipaddr[1] & 0xFF) << 8) | ((auipaddr[2] & 0xFF) << 16) | ((auipaddr[3] & 0xFF) << 24);
    
    if (0 != wifi_tcpip_multicast_join(ipaddr)) {
        dbg_error("failed");
        return -1;
    }

    return 0;
}

int HAL_UDP_recvfrom(_IN_ intptr_t sockfd,
                     _OU_ NetworkAddr *p_remote,
                     _OU_ unsigned char *p_data,
                     _IN_ unsigned int datalen,
                     _IN_ unsigned int timeout_ms)
{
    int         ret = 0;
    UDP_Addr    udpaddr;

    ret = wifi_udp_read((uint8_t)sockfd, (uint8_t *)p_data, (int)datalen, (int)timeout_ms, &udpaddr);
    if (ret <= 0) {
        return -1;
    }

    p_remote->port = udpaddr.port;
    HAL_IP2Str(udpaddr.ipaddr, (char *)(p_remote->addr));
    dbg_trace("recv %d bytes from %s port %d", ret, (char *)(p_remote->addr), udpaddr.port);
    return ret;
}

int HAL_UDP_sendto(_IN_ intptr_t sockfd,
                   _IN_ const NetworkAddr *p_remote,
                   _IN_ const unsigned char *p_data,
                   _IN_ unsigned int datalen,
                   _IN_ unsigned int timeout_ms)
{
    int         ret = 0;
    UDP_Addr    udpaddr;
    int         ipaddr;
    int         auipaddr[4];

    sscanf((char *)p_remote->addr, "%d.%d.%d.%d", &auipaddr[0], &auipaddr[1], &auipaddr[2], &auipaddr[3]);
    ipaddr = (auipaddr[0] & 0xFF) |  ((auipaddr[1] & 0xFF) << 8) | ((auipaddr[2] & 0xFF) << 16) | ((auipaddr[3] & 0xFF) << 24);

    udpaddr.port = p_remote->port;
    udpaddr.ipaddr = ipaddr;

    ret = wifi_udp_write((uint8_t)sockfd, (uint8_t *)p_data, (int)datalen, (int)timeout_ms, &udpaddr);
    if (ret <= 0) {
        dbg_error("failed");
        return -1;
    }

    dbg_trace("send %d bytes to %s port %d", ret, (char *)p_remote->addr, udpaddr.port);
    return ret;
}

int HAL_UDP_close_without_connect(_IN_ intptr_t sockfd)
{
    if (0 != wifi_tcpip_udp_close((uint8_t)sockfd)) {
        dbg_error("failed");
        return -1;
    }

    return 0;
}



