import zigpy.types as t
from zigpy_blz.blz.types import * 

FRAME_SCHEMAS = {
    # Control Frames
    FrameId.ACK: (
        {},  # No request data
        {},  # No response data
    ),
    FrameId.ERROR: (
        {"error_code": t.uint8_t},  # Request schema
        {},  # No response data
    ),
    FrameId.RESET: (
        {},  # No request data
        {},  # Response schema
    ),
    FrameId.RESET_ACK: (
        {},  # No request data
        {"reset_reason": t.uint8_t},
    ),

    # Value Frames
    FrameId.GET_VALUE: (
        {"value_id": t.uint8_t},  # Request schema
        {"status": Status, "value_length": t.uint8_t, "value": Bytes},  # Response schema
    ),
    FrameId.SET_VALUE: (
        {"value_id": t.uint8_t, "value_length": t.uint8_t, "value": Bytes},  # Request schema
        {"status": Status},  # Response schema
    ),
    FrameId.GET_NODE_ID_BY_EUI64: (
        {"eui64": t.EUI64},  # Request schema
        {"status": Status, "node_id": t.uint16_t},  # Response schema
    ),
    FrameId.GET_EUI64_BY_NODE_ID: (
        {"node_id": t.uint16_t},  # Request schema
        {"status": Status, "eui64": t.EUI64},  # Response schema
    ),
    FrameId.GET_NEXT_ZDP_SEQUENCE_NUM: (
        {},  # No request data
        {"status": Status, "seq_num": t.uint8_t},  # Response schema
    ),
    FrameId.ADD_ENDPOINT: (
        {
            "endpoint": t.uint8_t,
            "profile_id": t.uint16_t,
            "device_id": t.uint16_t,
            "app_flags": t.uint8_t,
            "input_cluster_count": t.uint8_t,
            "output_cluster_count": t.uint8_t,
            "input_cluster_list": t.List[t.uint16_t],
            "output_cluster_list": t.List[t.uint16_t],
        },  # Request schema
        {"status": Status},  # Response schema
    ),

    # Networking Frames
    FrameId.GET_NETWORK_STATE: (
        {},  # No request data
        {"status": Status, "network_state": t.uint8_t},  # Response schema
    ),
    FrameId.START_SCAN: (
        {"scan_type": t.uint8_t, "duration": t.uint8_t, "channel_mask": t.uint32_t},  # Request schema
        {"status": Status},  # Response schema
    ),
    FrameId.ENERGY_SCAN_RESULT_CALLBACK: (
        {},  # No request data
        {"status": Status, "channel": t.uint8_t, "rssi": t.int8s},  # Response schema
    ),
    FrameId.NETWORK_SCAN_RESULT_CALLBACK: (
        {},  # No request data
        {
            "channel": t.uint8_t,
            "pan_id": t.uint16_t,
            "extended_pan_id": t.uint64_t,
            "association_permit": t.uint8_t,
            "stack_profile": t.uint8_t,
            "nwk_update_id": t.uint8_t,
            "beacon_lqi": t.uint8_t,
            "beacon_rssi": t.int8s,
        },  # Response schema
    ),
    FrameId.SCAN_COMPLETE_CALLBACK: (
        {},  # No request data
        {"status": Status},  # Response schema
    ),
    FrameId.STOP_SCAN: (
        {},  # No request data
        {"status": Status},  # Response schema
    ),
    FrameId.FORM_NETWORK: (
        {"ext_pan_id": t.uint64_t, "pan_id": t.uint16_t, "channel": t.uint8_t},  # Request schema
        {"status": Status},  # Response schema
    ),
    FrameId.JOIN_NETWORK: (
        {"ext_pan_id": t.uint64_t, "pan_id": t.uint16_t, "channel": t.uint8_t},  # Request schema
        {"status": Status},  # Response schema
    ),
    FrameId.LEAVE_NETWORK: (
        {},  # No request data
        {"status": Status},  # Response schema
    ),
    FrameId.PERMIT_JOINING: (
        {"duration": t.uint8_t},  # Request schema
        {"status": Status},  # Response schema
    ),
    FrameId.ENERGY_SCAN_REQUEST: (
        {"channel_mask": t.uint32_t, "duration": t.uint8_t},  # Request schema
        {"status": Status},  # Response schema
    ),
    FrameId.GET_NETWORK_PARAMETERS: (
        {},  # No request data
        {
            "status": Status,
            "node_type": t.uint8_t,
            "ext_pan_id": t.uint64_t,
            "pan_id": t.uint16_t,
            "tx_power": t.uint8_t,
            "channel": t.uint8_t,
            "nwk_manager": t.uint16_t,
            "nwk_update_id": t.uint8_t,
            "channel_mask": t.uint32_t,
        },  # Response schema
    ),
    # FrameId.GET_RADIO_PARAMETERS: (
    #     {},  # No request data
    #     {
    #         "status": Status,
    #         "tx_power": t.uint8_t,
    #         "channel": t.uint8_t,
    #     },  # Response schema
    # ),
    FrameId.GET_NEIGHBOR_TABLE_COUNT: (
        {},  # No request data
        {"status": Status, "count": t.uint16_t},  # Response schema
    ),
    FrameId.GET_NEIGHBOR_TABLE_ENTRY: (
        {"index": t.uint16_t},  # Request schema
        {
            "status": Status,
            "ext_address": t.uint64_t,
            "network_address": t.uint16_t,
            "device_type": t.uint8_t,
            "rx_on_when_idle": t.uint8_t,
            "link_quality": t.uint8_t,
            "outgoing_cost": t.uint8_t,
            "age": t.uint8_t,
        },  # Response schema
    ),
    FrameId.GET_SOURCE_ROUTE_TABLE_COUNT: (
        {},  # No request data
        {"status": Status, "count": t.uint16_t},  # Response schema
    ),
    FrameId.GET_SOURCE_ROUTE_TABLE_ENTRY: (
        {"index": t.uint16_t},  # Request schema
        {
            "status": Status,
            "network_address": t.uint16_t,
            "relay_count": t.uint8_t,
            "relay_list": t.List[t.uint16_t],
        },  # Response schema
    ),
    FrameId.GET_ROUTE_TABLE_COUNT: (
        {},  # No request data
        {"status": Status, "count": t.uint16_t},  # Response schema
    ),
    FrameId.GET_ROUTE_TABLE_ENTRY: (
        {"index": t.uint16_t},  # Request schema
        {
            "status": Status,
            "destination_address": t.uint16_t,
            "next_hop": t.uint16_t,
            "status_flags": t.uint8_t,
        },  # Response schema
    ),
    FrameId.SET_CONCENTRATOR: (
        {
            "concentrator": t.uint8_t,
            "radius": t.uint8_t,
            "multicast_radius": t.uint8_t,
            "route_discovery_time": t.uint16_t,
        },  # Request schema
        {"status": Status},  # Response schema
    ),
    FrameId.NETWORK_INIT: (
        {},  # No request data
        {"status": Status},  # Response schema
    ),
    FrameId.STACK_STATUS_CALLBACK: (
        {},  # No request data
        {"status": t.uint8_t},  # Response schema
    ),
    FrameId.DEVICE_JOIN_CALLBACK: (
        {},  # No request data
        {
            "eui64": t.EUI64,
            "node_id": t.uint16_t,
            "status": t.uint8_t,
        },  # Response schema
    ),
    FrameId.GET_NWK_PAYLOAD_LIMIT: (
        {"dst_addr": t.uint16_t},  # Request schema
        {"status": Status, "payload_limit": t.uint8_t},  # Response schema
    ),
    FrameId.NWK_STATUS_CALLBACK: (
        {},  # No request data
        {
            "status": t.uint8_t,
            "network_address": t.uint16_t,
            "ieee_address": t.EUI64,
        },  # Response schema
    ),

    # Security Frames
    FrameId.GET_NWK_SECURITY_INFOS: (
        {},  # No request data
        {
            "status": Status,
            "nwk_key": t.KeyData,
            "outgoing_frame_counter": t.uint32_t,
            "nwk_key_seq_num": t.uint8_t,
        },  # Response schema
    ),
    FrameId.SET_NWK_SECURITY_INFOS: (
        {
            "nwk_key": t.KeyData,
            "outgoing_frame_counter": t.uint32_t,
            "nwk_key_seq_num": t.uint8_t,
        },  # Request schema
        {"status": Status},  # Response schema
    ),
    FrameId.GET_GLOBAL_TC_LINK_KEY: (
        {},  # No request data
        {
            "status": Status,
            "link_key": t.KeyData,
            "outgoing_frame_counter": t.uint32_t,
            "trust_center_address": t.EUI64,
        },  # Response schema
    ),
    FrameId.SET_GLOBAL_TC_LINK_KEY: (
        {
            "link_key": t.KeyData,
            "outgoing_frame_counter": t.uint32_t,
        },  # Request schema
        {"status": Status},  # Response schema
    ),
    FrameId.GET_UNIQUE_TC_LINK_KEY: (
        {"index": t.uint16_t},  # Request schema
        {
            "status": Status,
            "link_key": t.KeyData,
            "outgoing_frame_counter": t.uint32_t,
            "device_ieee_address": t.EUI64,
        },  # Response schema
    ),
    FrameId.SET_UNIQUE_TC_LINK_KEY: (
        {
            "eui64": t.EUI64,
            "unique_tc_link_key": t.KeyData,
        },  # Request schema
        {"status": Status},  # Response schema
    ),

    # APS Data Frames
    FrameId.SEND_APS_DATA: (
        {
            "msg_type": t.uint8_t,
            "dst_short_addr": t.uint16_t,
            "profile_id": t.uint16_t,
            "cluster_id": t.uint16_t,
            "src_ep": t.uint8_t,
            "dst_ep": t.uint8_t,
            "tx_options": t.uint8_t,
            "radius": t.uint8_t,
            "message_tag": t.uint32_t,
            "payload_len": t.uint8_t,
            "payload": Bytes,  # Payload data will be fetched and appended as raw bytes
        },  # Request schema
        {"status": Status},  # Response schema
    ),
    FrameId.APS_DATA_INDICATION: (
        {},  # No request data
        {
            "profile_id": t.uint16_t,
            "cluster_id": t.uint16_t,
            "src_short_addr": t.uint16_t,
            "dst_short_addr": t.uint16_t,
            "src_ep": t.uint8_t,
            "dst_ep": t.uint8_t,
            "msg_type": t.uint8_t,
            "lqi": t.uint8_t,
            "rssi": t.int8s,
            "message_length": t.uint8_t,
            "message": Bytes,  # Message content as raw bytes
        },  # Response schema
    ),
    FrameId.APS_DATA_CONFIRM: (
        {},  # No request data
        {
            "profile_id": t.uint16_t,
            "cluster_id": t.uint16_t,
            "dst_short_addr": t.uint16_t,
            "src_ep": t.uint8_t,
            "dst_ep": t.uint8_t,
            "msg_type": t.uint8_t,
            "status": t.uint8_t,
            "message_tag": t.uint32_t,
        },  # Response schema
    ),
}