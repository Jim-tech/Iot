/* cubx.c
 *
 * Wiretap Library
 * Copyright (c) 2020 by Jim Lin <linjing_hust@126.com>
 *
 * File format support for Ubiqua Protocol Analyzer file format
 * Copyright (c) 2020 by Jim Lin <linjing_hust@126.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This wiretap is for a cubx file format reader. The format is
 * reverse engineere.
 *
 */

#include "config.h"
#include "wtap-int.h"
#include "file_wrappers.h"
#include "stdlib.h"
#include "string.h"

#include <epan/uat.h>
#include "sqlite3.h"

#ifdef WIN32
#include <tchar.h>
#endif

#define DEBUG 1

#define dbg_print(...) printf("[%s][%d]", __FUNCTION__, __LINE__);printf(__VA_ARGS__);printf("\r\n")

void wtap_register_cubx(void);

#define CUBX_MAGIC                      "SQLite format 3"
#define CUBX_TABLE_METADATA             0x01
#define CUBX_TABLE_PACKETS              0x02
#define CUBX_TABLE_KEYS                 0x04

#define GP_KEY_UAT_NAME                 "ZigBee GP Security Keys"
#define ZB_KEY_UAT_NAME                 "Pre-configured Keys"
#define GP_KEY_FILE_NAME                "zigbee_gp_keys"
#define ZB_KEY_FILE_NAME                "zigbee_pc_keys"
#define KEY_FORMAT_STR                  "\"%s\",\"Normal\",\"\"\n"

/* Private data needed to read the file initially. */
typedef struct {
    char              db_filename[MAX_PATH];
    sqlite3          *pdb;
    sqlite3_stmt     *pstatement;
    unsigned int      packet_num;
    unsigned int      packet_id;
} cubx_info_t;

WS_DLL_PUBLIC void* uat_add_record(uat_t *uat, const void *orig_rec_ptr, gboolean valid_rec);
WS_DLL_PUBLIC uat_t* uat_get_table_by_name(const char* name);
WS_DLL_PUBLIC void uat_clear(uat_t *uat);
WS_DLL_PUBLIC gboolean uat_load(uat_t* uat_in, const gchar *filename, char** err);
WS_DLL_PUBLIC char *get_profiles_dir(void);

static gboolean cubx_read(wtap *wth, wtap_rec *rec, Buffer *buf,
                             int *err, gchar **err_info,
                             gint64 *data_offset);
static gboolean cubx_seek_read(wtap *wth, gint64 seek_off,
                                  wtap_rec *rec, Buffer *buf,
                                  int *err, gchar **err_info);
static gboolean cubx_read_packet(wtap *wth, FILE_T fh,
                                    wtap_rec *rec, Buffer *buf,
                                    int *err, gchar **err_info);

static int          cubx_file_type_subtype;
static uat_t       *g_p_gpkey_table_uat = NULL;
static uat_t       *g_p_zbkey_table_uat = NULL;

static int cubx_dup2tempfile(wtap *wth, int *err, char tmpfname[MAX_PATH])
{
    int     ret = -1;
    size_t  wrlen = 0;
    size_t  rdlen = 0;
    unsigned char buf[4096] = {0};

    #ifdef WIN32
    TCHAR temp_path[MAX_PATH] = {0};
    TCHAR temp_filename[MAX_PATH] = {0};
    
    ret = GetTempPath(MAX_PATH, temp_path);
    if (ret <= 0 || ret > MAX_PATH) {
        dbg_print("failed");
        return -1;
    }

    wprintf(_T("temp_path=[%s]\r\n"), temp_path);

    ret = GetTempFileName(temp_path, _T("wshark_"), 0, temp_filename);
    if (0 == ret) {
        dbg_print("failed");
        return -1;
    }

    wprintf(_T("db_filename=[%s]\r\n"), temp_filename);
    snprintf(tmpfname, MAX_PATH-1, "%ws", temp_filename);
    dbg_print("db_filename=%s", tmpfname);
    #endif

    FILE *fp = fopen(tmpfname, "wb+");
    if (NULL == fp) {
        dbg_print("failed");
        return -1;
    }

    ret = 0;
    file_seek(wth->fh, 0, SEEK_SET, err);
    while (1){
        rdlen = file_read(buf, sizeof(buf), wth->fh);
        if (rdlen == sizeof(buf)) {
            wrlen = fwrite(buf, sizeof(buf), 1, fp);
        } else if (rdlen > 0) {
            wrlen = fwrite(buf, 1, rdlen, fp);
        } else if (rdlen < 0) {
            fclose(fp);
            dbg_print("failed");
            ret = -1;
            break;
        } else {
            break;
        }
        
        if (rdlen < sizeof(buf)) {
            break;
        }
    }
    
    fclose(fp);
    
    return ret;
}

static int cubx_check_systemtbl(cubx_info_t *cubx_info)
{
    int               ret = 0;
    int               table_mask = 0;
    char             *p_name = NULL;
    sqlite3_stmt     *pstatement;

    typedef struct {
        char *p_name;
        int   bitval;
    }name_bit_map;

    name_bit_map map[] = {
        {"Metadata", CUBX_TABLE_METADATA},
        {"Packets",  CUBX_TABLE_PACKETS},
        {"Keys",     CUBX_TABLE_KEYS},
    };

    ret = sqlite3_prepare_v2(cubx_info->pdb, 
                             "select name from sqlite_master where type='table'", 
                             -1, 
                             &pstatement, 
                             NULL);
    if (SQLITE_OK != ret) {
        dbg_print("failed, ret=%d", ret);
        return -1;
    }

    while (SQLITE_ROW == sqlite3_step(pstatement)) {
        p_name = (char *)sqlite3_column_text(pstatement, 0);
        if (NULL != p_name) {
            for (int i = 0; i < sizeof(map)/sizeof(name_bit_map); i++) {
                if (strcmp(p_name, map[i].p_name) == 0) {
                    table_mask |= map[i].bitval;
                    break;
                }
            }
        }
    }

    sqlite3_finalize(pstatement);
    
    if ((CUBX_TABLE_METADATA | CUBX_TABLE_PACKETS) != (table_mask & (CUBX_TABLE_METADATA | CUBX_TABLE_PACKETS))) {
        dbg_print("failed");
        return -1;
    } else {
        return 0;
    }
}

static int cubx_get_pktnum(cubx_info_t *cubx_info)
{
    int               ret = 0;
    sqlite3_stmt     *pstatement;

    ret = sqlite3_prepare_v2(cubx_info->pdb, 
                             "select count(*) from Packets", 
                             -1, 
                             &pstatement, 
                             NULL);
    if (SQLITE_OK != ret) {
        dbg_print("failed, ret=%d", ret);
        return -1;
    }

    if (SQLITE_ROW != sqlite3_step(pstatement)) {
        dbg_print("failed, ret=%d", ret);
        sqlite3_finalize(pstatement);
        return -1;
    }

    cubx_info->packet_num = sqlite3_column_int(pstatement, 0);

    dbg_print("cubx_info->packet_num=%d", cubx_info->packet_num);

    sqlite3_finalize(pstatement);
    return 0;
}

static int cubx_readpkt_start(cubx_info_t *cubx_info)
{
    int   ret = 0;

    ret = sqlite3_prepare_v2(cubx_info->pdb, 
                             "select * from Packets", 
                             -1, 
                             &(cubx_info->pstatement), 
                             NULL);
    if (SQLITE_OK != ret) {
        dbg_print("failed, ret=%d", ret);
        return -1;
    }

    return 0;
}

static void cubx_readpkt_stop(cubx_info_t *cubx_info)
{
    sqlite3_finalize(cubx_info->pstatement);
    cubx_info->pstatement = NULL;
}

static int cubx_init_key_file()
{
    char         *p_prof_dir = NULL;
    char          prof_name[512] = {0};
    char          key_filename[512] = {0};
    const char   *profilelist[] = {
        ZB_KEY_FILE_NAME,
        GP_KEY_FILE_NAME,
    };
    
    FILE             *fp_key = NULL;
    FILE             *fp_prof = NULL;
    char              szline[256] = {0};

    p_prof_dir = get_profiles_dir();

    for (int i = 0; i < sizeof(profilelist)/sizeof(const char *); i++) {
        snprintf(key_filename, sizeof(key_filename)-1, "%s_tmp", profilelist[i]);
        fp_key = fopen(key_filename, "w+");
        if (NULL != fp_key) {
            if (NULL != p_prof_dir) {
                snprintf(prof_name, sizeof(prof_name)-1, "%s\\..\\%s", p_prof_dir, profilelist[i]);
                fp_prof = fopen(prof_name, "r");
                if (NULL != fp_prof) {
                    while (fgets(szline, sizeof(szline)-1, fp_prof) != NULL) {
                        fprintf(fp_key, szline);
                    }
                    fclose(fp_prof);
                }
            }
            fclose(fp_key);
        }
    }

    return 0;
}

static int cubx_deinit_key_file(gboolean update)
{
    uat_t    *p_uat = NULL;
    gchar    *err;
    char      key_filename[512] = {0};

    typedef struct {
        char    *p_uat_name;
        char    *p_file_name;
    }uat_list;

    uat_list list[] = {
        {ZB_KEY_UAT_NAME, ZB_KEY_FILE_NAME},
        {GP_KEY_UAT_NAME, GP_KEY_FILE_NAME},
    };

    for (int i = 0; i < sizeof(list)/sizeof(uat_list); i++) {
        snprintf(key_filename, sizeof(key_filename)-1, "%s_tmp", list[i].p_file_name);
        
        if (update) {
            p_uat = uat_get_table_by_name(list[i].p_uat_name);
            if (NULL == p_uat) {
                dbg_print("find uat (%s) fail", list[i].p_uat_name);
                return -1;
            } else {
                uat_clear(p_uat);
                if (TRUE != uat_load(p_uat, key_filename, &err)) {
                    dbg_print("update uat by (%s) fail err=%s", key_filename, err);
                    g_free(err);
                    return -1;
                }
            }
        }

        remove(key_filename);
    }

    return 0;
}

static int cubx_add_to_keyfile(char *filename, char *p_key)
{
    FILE     *fp;
    char      key_filename[512] = {0};

    snprintf(key_filename, sizeof(key_filename)-1, "%s_tmp", filename);
    fp = fopen(key_filename, "a+");
    if (NULL == fp) {
        dbg_print("open key file (%s) fail", key_filename);
        return -1;
    }

    fprintf(fp, KEY_FORMAT_STR, p_key);
    fclose(fp);
    return 0;
}

static int cubx_add_key(char *p_key, char *p_type)
{
    typedef struct
    {
        char *p_type;
        char *p_filename;
    }key_type_file_map;

    key_type_file_map map[] = {
        {"NetworkKey", ZB_KEY_FILE_NAME},
        {"LinkKey", ZB_KEY_FILE_NAME},
        {"ZigBeeGreenPowerKey", GP_KEY_FILE_NAME},
    };

    for (int i = 0; i < sizeof(map)/sizeof(key_type_file_map); i++) {
        if (0 == strcmp(p_type, map[i].p_type)) {
            return cubx_add_to_keyfile(map[i].p_filename, p_key);
        }
    }
    
    return -1;
}

static int cubx_add_security_keys(cubx_info_t *cubx_info)
{
    int               ret = 0;
    char             *p_key;
    char             *p_type;
    sqlite3_stmt     *pstatement;

    if (0 != cubx_init_key_file()) {
        dbg_print("failed, ret=%d", ret);
        return -1;
    }

    ret = sqlite3_prepare_v2(cubx_info->pdb, 
                             "select hex(Key),Type from Keys", 
                             -1, 
                             &pstatement, 
                             NULL);
    if (SQLITE_OK != ret) {
        dbg_print("failed, ret=%d", ret);
        cubx_deinit_key_file(FALSE);
        return -1;
    }

    while (SQLITE_ROW == sqlite3_step(pstatement)) {
        p_key = (char *)sqlite3_column_text(pstatement, 0);
        p_type = (char *)sqlite3_column_text(pstatement, 1);
        
        dbg_print("[%s] Key=[%s]", p_type, p_key);
        cubx_add_key(p_key, p_type);
    }
    
    sqlite3_finalize(pstatement);
    
    if (0 != cubx_deinit_key_file(TRUE)) {
        dbg_print("failed, ret=%d", ret);
        return -1;
    }
    
    return 0;
}

static int cubx_db_connect(cubx_info_t *cubx_info)
{
    int   ret = 0;

    if (NULL != cubx_info->pdb) {
        return 0;
    }

    ret = sqlite3_open(cubx_info->db_filename, &(cubx_info->pdb));
    if (0 != ret) {
        dbg_print("failed");
        return -1;
    }

    return 0;
}

static void cubx_db_disconnect(cubx_info_t *cubx_info)
{
    if (cubx_info->pstatement) {
        cubx_readpkt_stop(cubx_info);
    }
    
    sqlite3_close(cubx_info->pdb);
    cubx_info->pdb = NULL;
    return;
}


static wtap_open_return_val
cubx_open(wtap *wth, int *err, char **err_info)
{
    int     ret = 0;
    gchar   magic[16];

    dbg_print("this is a test");

    if (!wtap_read_bytes(wth->fh, magic, sizeof magic, err, err_info)) {
        if (*err != WTAP_ERR_SHORT_READ)
            return WTAP_OPEN_ERROR;
        return WTAP_OPEN_NOT_MINE;
    }

    /* Check the file magic */
    if (strcmp(magic, CUBX_MAGIC) != 0)
    {
        return WTAP_OPEN_NOT_MINE;
    }

    cubx_info_t *cubx_info = (cubx_info_t *)g_malloc(sizeof(cubx_info_t));
    if (NULL == cubx_info) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = "not enough mem";
        dbg_print("failed");
        return WTAP_OPEN_ERROR;
    }

    memset(cubx_info, 0, sizeof(cubx_info_t));

    /* create a temp file, and copy this file to temp file */
    if (0 != cubx_dup2tempfile(wth, err, cubx_info->db_filename)) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = "dup to tempfile fail";
        dbg_print("failed");
        return WTAP_OPEN_ERROR;
    }

    file_seek(wth->fh, 0, SEEK_SET, err);

    /* check if it's valid  */
    if (0 != cubx_db_connect(cubx_info)) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = "connect db fail";
        dbg_print("failed");
        return WTAP_OPEN_ERROR;
    }
    
    ret = 0;
    ret |= cubx_check_systemtbl(cubx_info);
    ret |= cubx_get_pktnum(cubx_info);
    ret |= cubx_readpkt_start(cubx_info);
    ret |= cubx_add_security_keys(cubx_info);
    if (0 != ret) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = "invalid file";
        dbg_print("failed");

        cubx_db_disconnect(cubx_info);
        return WTAP_OPEN_ERROR;
    }
    
    wth->priv = (void *)cubx_info;
    wth->subtype_read = cubx_read;
    wth->subtype_seek_read = cubx_seek_read;
    wth->file_type_subtype = cubx_file_type_subtype;
    wth->file_encap = WTAP_ENCAP_IEEE802_15_4_NOFCS;
    wth->file_tsprec = WTAP_TSPREC_USEC;
    wth->snapshot_length = 0;

    return WTAP_OPEN_MINE;    
}

/*
 * Sequential read with offset reporting.
 * Read the next frame in the file and adjust for the multiframe size
 * indication. Report back where reading of this frame started to
 * support subsequent random access read.
 */
static gboolean
cubx_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err, gchar **err_info,
             gint64 *data_offset)
{
    cubx_info_t *cubx_info = (cubx_info_t *)wth->priv;

    /*packet start from 1  */
    *data_offset = cubx_info->packet_id + 1;

    file_seek(wth->fh, cubx_info->packet_id + 1, SEEK_SET, err);

    if (NULL == cubx_info->pdb) {
        cubx_db_connect(cubx_info);
    }

    if (cubx_info->packet_id >= cubx_info->packet_num) {
    //if (cubx_info->packet_id >= 1) {
        cubx_db_disconnect(cubx_info);
        return FALSE;
    }

    if (SQLITE_ROW != sqlite3_step(cubx_info->pstatement)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = "read pkt fail";
        cubx_db_disconnect(cubx_info);
        return FALSE;
    }

    double ts = sqlite3_column_double(cubx_info->pstatement, 4); //column 4 is Timestamp
    rec->rec_type = REC_TYPE_PACKET;
    rec->presence_flags = WTAP_HAS_TS | WTAP_HAS_CAP_LEN;
    rec->tsprec = WTAP_TSPREC_NSEC;
    rec->ts.secs = (unsigned int)ts;
    rec->ts.nsecs = (unsigned int)((ts - (double)rec->ts.secs) * 1E6);

    //dbg_print("ts=%ld tns=%ld", rec->ts.secs, rec->ts.nsecs);
    
    unsigned int len = sqlite3_column_bytes(cubx_info->pstatement, 1); //column 1 is Raw
    if (len <= 2) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = "read pkt fail 3";
        cubx_db_disconnect(cubx_info);
        return FALSE;
    }

    len -= 2; //strip last two bytes as no FCS
    
    ws_buffer_assure_space(buf, len);
    memcpy(ws_buffer_start_ptr(buf), sqlite3_column_blob(cubx_info->pstatement, 1), len);

    rec->rec_header.packet_header.caplen = len;
    rec->rec_header.packet_header.len = len;
    
    cubx_info->packet_id++;
    return TRUE;
}

/*
 * Random access read.
 * Read the frame at the given offset in the file. Store the frame data
 * in a buffer and fill in the packet header info.
 */
static gboolean
cubx_seek_read(wtap *wth, gint64 seek_off, wtap_rec *rec,
                  Buffer *buf, int *err, gchar **err_info)
{
    int           ret = 0;
    cubx_info_t  *cubx_info = (cubx_info_t *)wth->priv;
    unsigned int  pkt_id = (unsigned int)seek_off;
    char          sz_sqlcmd[256] = {0};

    dbg_print("seek_off=%lld", seek_off);

    file_seek(wth->random_fh, seek_off, SEEK_SET, err);
    
    if (NULL == cubx_info->pdb) {
        cubx_db_connect(cubx_info);
    }

    snprintf(sz_sqlcmd, sizeof(sz_sqlcmd)-1, "select * from Packets where id=%d", pkt_id);
    ret = sqlite3_prepare_v2(cubx_info->pdb, 
                             sz_sqlcmd, 
                             -1, 
                             &(cubx_info->pstatement), 
                             NULL);
    if (SQLITE_OK != ret) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = "read pkt fail 1";
        cubx_db_disconnect(cubx_info);
        return FALSE;
    }

    if (SQLITE_ROW != sqlite3_step(cubx_info->pstatement)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = "read pkt fail 2";
        cubx_db_disconnect(cubx_info);
        return FALSE;
    }

    double ts = sqlite3_column_double(cubx_info->pstatement, 4); //column 4 is Timestamp
    rec->rec_type = REC_TYPE_PACKET;
    rec->presence_flags = WTAP_HAS_TS | WTAP_HAS_CAP_LEN;
    rec->tsprec = WTAP_TSPREC_NSEC;
    rec->ts.secs = (unsigned int)ts;
    rec->ts.nsecs = (unsigned int)((ts - (double)rec->ts.secs) * 1E6);

    //dbg_print("ts=%ld tns=%ld", rec->ts.secs, rec->ts.nsecs);
    
    unsigned int len = sqlite3_column_bytes(cubx_info->pstatement, 1); //column 1 is Raw

    if (len <= 2) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = "read pkt fail 3";
        cubx_db_disconnect(cubx_info);
        return FALSE;
    }

    len -= 2; //strip last two bytes as no FCS
    ws_buffer_assure_space(buf, len);
    memcpy(ws_buffer_start_ptr(buf), sqlite3_column_blob(cubx_info->pstatement, 1), len);

    rec->rec_header.packet_header.caplen = len;
    rec->rec_header.packet_header.len = len;

    if (pkt_id >= cubx_info->packet_num) {
        file_seek(wth->random_fh, 0, SEEK_END, err);
        cubx_db_disconnect(cubx_info);
    }

    return TRUE;
}

void
wtap_register_cubx(void)
{
    struct open_info oi = {
        "Ubiqua Zigbee Capture",
        OPEN_INFO_HEURISTIC,
        cubx_open,
        "cubx",
        NULL,
        NULL
    };

    wtap_register_open_info(&oi, FALSE);

    struct file_type_subtype_info fi = {
        "Ubiqua Zigbee Capture",
        "cubx",
        "cubx",
        "cubx",
        FALSE,
        FALSE,
        0,
        NULL,
        NULL,
        NULL
    };

    cubx_file_type_subtype =
        wtap_register_file_type_subtypes(&fi, WTAP_FILE_TYPE_SUBTYPE_UNKNOWN);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
