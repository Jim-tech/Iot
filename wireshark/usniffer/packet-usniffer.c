/* packet-usniffer.c
 *
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <wsutil/str_util.h>
#include "packet-usniffer.h"

/*
 *
 */

void proto_register_usniffer(void);
void proto_reg_handoff_usniffer(void);


static int proto_usniffer = -1;
static int usniffer_encap_type = -1;

static int hf_usniffer_radio_ch = -1;
static int hf_usniffer_radio_rssi = -1;

static dissector_handle_t  usniffer_handle;
static dissector_handle_t  ieee802154_nofcs_handle;

static gint ett_usniffer_radio = -1;

static int
dissect_usniffer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tvbuff_t            *payload;
    proto_item          *proto_root;
    proto_tree          *radio_tree;
    guint                len = tvb_captured_length(tvb);
    guint8               ch;
    gint8                rssi;

    ch = tvb_get_guint8(tvb, len - 2);
    rssi = tvb_get_gint8(tvb, len - 1);

    payload = tvb_new_subset_length(tvb, 0, len - 2); //last two bytes is ch and rssi
    call_dissector_with_data(ieee802154_nofcs_handle, payload, pinfo, tree, data);

    proto_root = proto_tree_add_item(tree, proto_usniffer, tvb, 0, -1, ENC_NA);
    radio_tree = proto_item_add_subtree(proto_root, ett_usniffer_radio);

    proto_tree_add_uint(radio_tree, hf_usniffer_radio_ch, tvb, len - 2, 1, ch);
    proto_tree_add_int(radio_tree, hf_usniffer_radio_rssi, tvb, len - 1, 1, rssi);
    
    return len;
}


void
proto_register_usniffer(void)
{
    static hf_register_info hf[] = {
		{ &hf_usniffer_radio_ch, { "Radio Channel", "radio.ch", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_usniffer_radio_rssi, { "Radio RSSI", "radio.rssi", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    };

    /* radio info subtrees */
    static gint *ett[] = {
        &ett_usniffer_radio,
    };

    proto_usniffer = proto_register_protocol("Usniffer Radio Info", "usniffer", "usniffer");
    proto_register_field_array(proto_usniffer, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    
    usniffer_handle = register_dissector("usniffer", dissect_usniffer, proto_usniffer);

    usniffer_encap_type = wtap_register_encap_type("IoT Unified Sniffer", "usniffer");
}

void
proto_reg_handoff_usniffer(void)
{
    ieee802154_nofcs_handle = find_dissector("wpan_nofcs");
    
    dissector_add_uint("wtap_encap", usniffer_encap_type, usniffer_handle);
}
