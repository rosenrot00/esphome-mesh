"""Encrypted mesh routing with an ESP-NOW transport and dual-stack IP fallback."""

import re

import esphome.codegen as cg
from esphome.components.esp32 import (
    VARIANT_ESP32,
    VARIANT_ESP32C3,
    VARIANT_ESP32C5,
    VARIANT_ESP32C6,
    VARIANT_ESP32S3,
    add_idf_sdkconfig_option,
    get_esp32_variant,
    include_builtin_idf_component,
    only_on_variant,
    request_wifi,
)
import esphome.config_validation as cv
from esphome.const import (
    CONF_CHANNEL,
    CONF_GATEWAY,
    CONF_ID,
    CONF_KEY,
    CONF_MAC_ADDRESS,
    CONF_TYPE,
    KEY_CORE,
    KEY_FRAMEWORK_VERSION,
)
from esphome.core import CORE
import esphome.final_validate as fv
from esphome.types import ConfigType

AUTO_LOAD = ["network", "espnow_driver"]
CODEOWNERS = ["@rosenrot00"]
CONFLICTS_WITH = ["espnow"]  # The common SDK owner grants one exclusive consumer lease.
DEPENDENCIES = ["esp32"]
DOMAIN = "mesh"

mesh_ns = cg.esphome_ns.namespace("mesh")
MeshComponent = mesh_ns.class_("MeshComponent", cg.Component)

CONF_NODE_ID = "node_id"
CONF_PMK = "pmk"
CONF_LMK = "lmk"
CONF_PEERS = "peers"
CONF_ALLOWED_NODE_IDS = "allowed_node_ids"
CONF_IP_GATEWAY = "ip_gateway"
CONF_IP_GATEWAYS = "ip_gateways"
CONF_IP_PEER_MACS = "ip_peer_macs"
CONF_IP_DISCOVERY = "ip_discovery"
CONF_ROUTE_SELECTION = "route_selection"
CONF_MAX_NODES = "max_nodes"
CONF_DISCOVERY_ASSEMBLY_SLOTS = "discovery_assembly_slots"


def key_16_bytes(value: str) -> str:
    value = cv.string_strict(value)
    if not re.fullmatch(r"[0-9a-fA-F]{32}", value):
        raise cv.Invalid("Expected exactly 32 hexadecimal characters (16 bytes)")
    return value.lower()


def key_32_bytes(value: str) -> str:
    value = cv.string_strict(value)
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise cv.Invalid(
            "Expected a randomly generated 32-byte mesh key (64 hexadecimal characters)"
        )
    return value.lower()


def validate_framework(config: ConfigType) -> ConfigType:
    # ESP-IDF 6 replaces the legacy mbedTLS message-digest API. Reject it
    # explicitly until the transport/security integration is qualified there.
    if CORE.data[KEY_CORE][KEY_FRAMEWORK_VERSION] >= cv.Version(6, 0, 0):
        raise cv.Invalid(
            "mesh requires ESP-IDF >=5.5 and <6.0; ESP-IDF 6 is not yet supported"
        )
    return config


def validate_topology(config: ConfigType) -> ConfigType:
    automatic = CONF_KEY in config
    max_nodes = config[CONF_MAX_NODES]
    config.setdefault(CONF_DISCOVERY_ASSEMBLY_SLOTS, max_nodes)
    if config[CONF_DISCOVERY_ASSEMBLY_SLOTS] > max_nodes:
        raise cv.Invalid("discovery_assembly_slots must not exceed max_nodes")
    if not automatic and max_nodes != 16:
        raise cv.Invalid("max_nodes below 16 requires automatic key mode")
    own_id = config.get(CONF_NODE_ID, 0)
    if own_id > max_nodes:
        raise cv.Invalid("node_id exceeds max_nodes")
    if not automatic:
        if not config[CONF_GATEWAY]:
            raise cv.Invalid(
                "gateway requires key; manual mode uses ip_gateway or ip_gateways"
            )
        for required in [
            CONF_NODE_ID,
            CONF_CHANNEL,
            CONF_PMK,
            CONF_ALLOWED_NODE_IDS,
            CONF_PEERS,
        ]:
            if required not in config:
                raise cv.Invalid(
                    f"{required} is required in manually provisioned mode; use key for automatic membership"
                )
    elif CONF_PMK in config:
        raise cv.Invalid("key derives the ESP-NOW PMK; do not also configure pmk")
    own_id = config.get(CONF_NODE_ID, 0)
    allowed = config.get(
        CONF_ALLOWED_NODE_IDS, list(range(1, config[CONF_MAX_NODES] + 1))
    )
    if any(node > max_nodes for node in allowed):
        raise cv.Invalid("allowed_node_ids exceeds max_nodes")
    if (
        not allowed
        or len(allowed) != len(set(allowed))
        or (own_id and own_id not in allowed)
    ):
        raise cv.Invalid("allowed_node_ids must be unique and include this node_id")
    if CONF_IP_GATEWAY in config and config[CONF_IP_GATEWAY] not in allowed:
        raise cv.Invalid("ip_gateway must be in allowed_node_ids")
    if CONF_IP_GATEWAY in config and CONF_IP_GATEWAYS in config:
        raise cv.Invalid("Use either fixed ip_gateway or dynamic ip_gateways, not both")
    gateways = config.get(CONF_IP_GATEWAYS, [])
    if CONF_IP_GATEWAYS in config and (
        not gateways
        or len(gateways) != len(set(gateways))
        or any(node not in allowed for node in gateways)
    ):
        raise cv.Invalid("ip_gateways must be nonempty, unique and in allowed_node_ids")
    if CONF_IP_GATEWAY in config:
        gateways = [config[CONF_IP_GATEWAY]]
    peer_ids, peer_macs = set(), set()
    identity_macs = {}
    for peer in config[CONF_IP_PEER_MACS]:
        node, mac = peer[CONF_NODE_ID], tuple(peer[CONF_MAC_ADDRESS].parts)
        if (
            node not in allowed
            or node == own_id
            or node in peer_ids
            or mac in peer_macs
            or mac[0] & 1
            or not any(mac)
        ):
            raise cv.Invalid(
                "ip_peer_macs requires unique allowed remote IDs and nonzero unicast MACs"
            )
        peer_ids.add(node)
        peer_macs.add(mac)
        identity_macs[node] = mac
    ids, macs = set(), set()
    for peer in config.get(CONF_PEERS, []):
        if not automatic and (CONF_NODE_ID not in peer or CONF_LMK not in peer):
            raise cv.Invalid("Manual peers require node_id and lmk")
        if automatic and CONF_LMK in peer:
            raise cv.Invalid(
                "key derives pairwise link keys; lmk belongs to manually provisioned mode"
            )
        node_id = peer.get(CONF_NODE_ID, 0)
        mac = tuple(peer[CONF_MAC_ADDRESS].parts)
        if node_id and (node_id == own_id or node_id in ids):
            raise cv.Invalid(
                "Each peer needs a unique node_id different from this node"
            )
        if node_id and node_id not in allowed:
            raise cv.Invalid("Every peer node_id must be in allowed_node_ids")
        if mac in macs or mac[0] & 1 or not any(mac):
            raise cv.Invalid(
                "Peer MAC addresses must be unique, nonzero unicast addresses"
            )
        if node_id:
            ids.add(node_id)
            if node_id in identity_macs and identity_macs[node_id] != mac:
                raise cv.Invalid(
                    "peers and ip_peer_macs must bind each node_id to the same MAC address"
                )
            if any(
                node != node_id and address == mac
                for node, address in identity_macs.items()
            ):
                raise cv.Invalid(
                    "peers and ip_peer_macs must not bind a MAC address to different node_ids"
                )
            identity_macs[node_id] = mac
        macs.add(mac)
    if CONF_PEERS in config and not 1 <= len(macs) < max_nodes:
        raise cv.Invalid(
            f"Configure 1..{max_nodes - 1} encrypted peers for max_nodes: {max_nodes}"
        )
    if not automatic and gateways and set(identity_macs) != set(allowed) - {own_id}:
        raise cv.Invalid(
            "Manual IP mesh requires an identity MAC for every allowed remote node in peers or ip_peer_macs; "
            "use key for automatic identity discovery"
        )
    if automatic:
        config.setdefault(CONF_CHANNEL, 1)
    return config


CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(MeshComponent),
            cv.Optional(CONF_TYPE, default="espnow"): cv.one_of("espnow", lower=True),
            cv.Optional(CONF_KEY): cv.sensitive(key_32_bytes),
            cv.Optional(CONF_GATEWAY, default=True): cv.boolean,
            cv.Optional(CONF_MAX_NODES, default=8): cv.All(
                cv.int_, cv.one_of(4, 8, 16)
            ),
            cv.Optional(CONF_DISCOVERY_ASSEMBLY_SLOTS): cv.int_range(min=1, max=16),
            cv.Optional(CONF_NODE_ID): cv.int_range(min=1, max=16),
            cv.Optional(CONF_CHANNEL): cv.int_range(min=1, max=14),
            cv.Optional(CONF_PMK): cv.sensitive(key_16_bytes),
            cv.Optional(CONF_ALLOWED_NODE_IDS): cv.ensure_list(
                cv.int_range(min=1, max=16)
            ),
            cv.Optional(CONF_PEERS): cv.ensure_list(
                cv.Schema(
                    {
                        cv.Optional(CONF_NODE_ID): cv.int_range(min=1, max=16),
                        cv.Required(CONF_MAC_ADDRESS): cv.mac_address,
                        cv.Optional(CONF_LMK): cv.sensitive(key_16_bytes),
                    }
                )
            ),
            cv.Optional(CONF_IP_GATEWAY): cv.int_range(min=1, max=16),
            cv.Optional(CONF_IP_GATEWAYS): cv.ensure_list(cv.int_range(min=1, max=16)),
            cv.Optional(CONF_IP_DISCOVERY): cv.boolean,
            cv.Optional(CONF_ROUTE_SELECTION, default="shortest"): cv.one_of(
                "stable", "shortest", lower=True
            ),
            cv.Optional(CONF_IP_PEER_MACS, default=[]): cv.ensure_list(
                cv.Schema(
                    {
                        cv.Required(CONF_NODE_ID): cv.int_range(min=1, max=16),
                        cv.Required(CONF_MAC_ADDRESS): cv.mac_address,
                    }
                )
            ),
        }
    ).extend(cv.COMPONENT_SCHEMA),
    cv.only_on_esp32,
    only_on_variant(
        supported=[
            VARIANT_ESP32,
            VARIANT_ESP32C3,
            VARIANT_ESP32C5,
            VARIANT_ESP32C6,
            VARIANT_ESP32S3,
        ]
    ),
    cv.require_framework_version(esp_idf=cv.Version(5, 5, 0)),
    validate_framework,
    validate_topology,
)


def validate_boot_mode(config: ConfigType) -> ConfigType:
    full_config = fv.full_config.get()
    if CONF_KEY in config or CONF_IP_GATEWAY in config or CONF_IP_GATEWAYS in config:
        from esphome.components import network

        network.register_connection_provider()
    if get_esp32_variant() == VARIANT_ESP32C5 and "wifi" in full_config:
        from esphome.components import wifi

        native = full_config["wifi"]
        band = native.get(wifi.CONF_BAND_MODE)
        if band is not None and str(band) != "2.4GHZ":
            raise cv.Invalid(
                "ESP32-C5 mesh requires a shared 2.4 GHz radio channel; "
                "wifi.band_mode AUTO and 5GHZ are not supported. "
                "Omit band_mode or use 2.4GHZ."
            )
        # Final validation runs before every component's code generation.
        # Use Wi-Fi's validated enum so its normal codegen applies the default.
        if band is None:
            native[wifi.CONF_BAND_MODE] = cv.enum(wifi.WIFI_BAND_MODES, upper=True)(
                "2.4GHZ"
            )
    native_lan = "wifi" in full_config or "ethernet" in full_config
    if (
        full_config.get("network", {}).get("enable_ipv6", False)
        and CONF_KEY not in config
    ):
        raise cv.Invalid(
            "mesh IPv6 requires automatic key mode to authenticate the IPv6 proxy capability on every peer"
        )
    if (
        full_config.get("network", {}).get("enable_ipv6", False)
        and full_config.get("network", {}).get("min_ipv6_addr_count", 0) > 2
    ):
        raise cv.Invalid(
            "mesh IPv6 supports one link-local and at most two preferred SLAAC addresses; min_ipv6_addr_count must be 0..2"
        )
    own_id = config.get(CONF_NODE_ID, 0)
    gateways = config.get(
        CONF_IP_GATEWAYS, [config[CONF_IP_GATEWAY]] if CONF_IP_GATEWAY in config else []
    )
    if (
        not native_lan
        and own_id
        and gateways
        and not any(node != own_id for node in gateways)
    ):
        raise cv.Invalid(
            "An IP mesh client without native Wi-Fi or Ethernet requires a remote gateway candidate"
        )
    if (
        (CONF_KEY in config or CONF_IP_GATEWAY in config or CONF_IP_GATEWAYS in config)
        and config.get(CONF_IP_DISCOVERY, False)
        and (
            full_config.get("mdns", {}).get("disabled", False)
            or "api" not in full_config
        )
    ):
        raise cv.Invalid(
            "ip_discovery requires enabled mdns and api; set ip_discovery: false to opt out"
        )
    return config


FINAL_VALIDATE_SCHEMA = validate_boot_mode


async def to_code(config: ConfigType) -> None:
    automatic = CONF_KEY in config
    # Portable translation units do not include ESPHome core/defines.h.
    cg.add_build_flag(f"-DMESH_MAX_NODES={config[CONF_MAX_NODES]}")
    cg.add_build_flag(
        f"-DMESH_DISCOVERY_ASSEMBLY_SLOTS={config[CONF_DISCOVERY_ASSEMBLY_SLOTS]}"
    )
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    include_builtin_idf_component("esp_wifi")
    # Ethernet-only firmware still needs the ESP-NOW radio. Register it with
    # ESP32's SDK configuration reconciler without creating a Wi-Fi component.
    request_wifi()
    if "ethernet" in CORE.config:
        cg.add_build_flag("-DMESH_HAS_ETHERNET=1")
    # The unassociated ESP-NOW radio follows the same policy as native Wi-Fi.
    # Other ESPHome components can deliberately override the requested mode.
    from esphome.components import wifi

    if "wifi" in CORE.config:
        # Keep periodic off-channel roaming scoped to active gateway service.
        wifi.enable_runtime_roaming_suppression()
    native_lan = "wifi" in CORE.config or "ethernet" in CORE.config
    requested_power_save = {"NONE": 0, "LIGHT": 1, "HIGH": 2}[
        str(CORE.config.get("wifi", {}).get("power_save_mode", "NONE"))
    ]
    effective_power_save = (
        0 if CORE.data.get(wifi.POWER_SAVE_OFF_REASONS_KEY) else requested_power_save
    )
    cg.add_define("MESH_WIFI_POWER_SAVE_MODE", requested_power_save)
    cg.add_define("MESH_WIFI_POWER_SAVE_EFFECTIVE_MODE", effective_power_save)
    add_idf_sdkconfig_option(
        "CONFIG_ESP_WIFI_ESPNOW_MAX_ENCRYPT_NUM",
        config[CONF_MAX_NODES] - 1 if automatic else max(7, len(config[CONF_PEERS])),
    )
    if CONF_NODE_ID in config:
        cg.add(var.set_node_id(config[CONF_NODE_ID]))
    if automatic:
        include_builtin_idf_component("mbedtls")
        cg.add_define("USE_MESH_AUTO")
        cg.add(var.set_network_key(list(bytes.fromhex(config[CONF_KEY]))))
        cg.add(var.set_auto_pinned_id(CONF_NODE_ID in config))
        cg.add(var.set_gateway_enabled(config[CONF_GATEWAY] and native_lan))
        gateways = config.get(
            CONF_IP_GATEWAYS,
            [config[CONF_IP_GATEWAY]]
            if CONF_IP_GATEWAY in config
            else config.get(
                CONF_ALLOWED_NODE_IDS, list(range(1, config[CONF_MAX_NODES] + 1))
            ),
        )
        for node_id in gateways:
            cg.add(var.add_ip_gateway(node_id))
    if CORE.config.get("network", {}).get("enable_ipv6", False):
        cg.add_build_flag("-DMESH_IPV6=1")
        # Portable sources do not all include core/defines.h.
        cg.add_build_flag(
            f"-DMESH_MIN_IPV6_ADDR_COUNT={CORE.config.get('network', {}).get('min_ipv6_addr_count', 0)}"
        )
    if automatic or CONF_IP_GATEWAY in config or CONF_IP_GATEWAYS in config:
        cg.add_define("USE_MESH_IP")
        cg.add_define("USE_NETWORK_PROVIDERS")
        if automatic:
            gateway_only = False
        elif CONF_IP_GATEWAYS in config:
            for node_id in config[CONF_IP_GATEWAYS]:
                cg.add(var.add_ip_gateway(node_id))
            # Candidates need both runtime roles: a Wi-Fi outage makes a former
            # gateway an ordinary client of another reachable candidate.
            client_only = config[CONF_NODE_ID] not in config[CONF_IP_GATEWAYS]
            if client_only:
                cg.add_build_flag("-DMESH_IP_CLIENT_ONLY=1")
            gateway_only = False
        else:
            cg.add(var.set_ip_gateway(config[CONF_IP_GATEWAY]))
            gateway_only = config[CONF_NODE_ID] == config[CONF_IP_GATEWAY]
            cg.add_build_flag(
                "-DMESH_IP_GATEWAY_ONLY=1"
                if gateway_only
                else "-DMESH_IP_CLIENT_ONLY=1"
            )
        # Global compiler flags keep all portable and ESPHome translation units
        # on the same layout, including files without core/defines.h.
        # Packet workspaces stay outside this stack. Retain headroom above the
        # SDK default for nested TCP responses from the mesh input callback.
        add_idf_sdkconfig_option("CONFIG_LWIP_TCPIP_TASK_STACK_SIZE", 4608)
        if config.get(
            CONF_IP_DISCOVERY,
            "api" in CORE.config
            and not CORE.config.get("mdns", {}).get("disabled", False),
        ):
            from esphome.components import mdns

            if not gateway_only:
                mdns.enable_mdns_storage()
            cg.add_define("USE_MESH_DISCOVERY")
            mdns_var = await cg.get_variable(CORE.config["mdns"][CONF_ID])
            cg.add(var.set_mdns_component(mdns_var))
            # Native services plus at most two delegated services per peer.
            add_idf_sdkconfig_option(
                "CONFIG_MDNS_MAX_SERVICES",
                2
                * len(
                    config.get(
                        CONF_ALLOWED_NODE_IDS,
                        list(range(1, config[CONF_MAX_NODES] + 1)),
                    )
                )
                + 4,
            )
    cg.add(var.set_channel(config[CONF_CHANNEL]))
    cg.add(var.set_route_stability(config[CONF_ROUTE_SELECTION] == "stable"))
    networks = CORE.config.get("wifi", {}).get("networks", [])
    cg.add_define("MESH_NATIVE_WIFI_NETWORK_COUNT", len(networks))
    for index, network in enumerate(networks):
        bssid = network.get("bssid")
        cg.add(
            var.set_native_wifi_network(
                index,
                network.get("ssid", ""),
                list(bssid.parts) if bssid else [0] * 6,
                network.get(CONF_CHANNEL, 0),
                bssid is not None,
                network.get("hidden", False),
                bool(network.get("password")) or "eap" in network,
            )
        )
    for peer in config[CONF_IP_PEER_MACS]:
        if automatic:
            cg.add(
                var.add_auto_identity_restriction(
                    peer[CONF_NODE_ID], peer[CONF_MAC_ADDRESS].parts
                )
            )
        else:
            cg.add(
                var.add_ip_peer_mac(peer[CONF_NODE_ID], peer[CONF_MAC_ADDRESS].parts)
            )
    if not automatic:
        cg.add(var.set_pmk(list(bytes.fromhex(config[CONF_PMK]))))
    for node_id in config.get(
        CONF_ALLOWED_NODE_IDS, list(range(1, config[CONF_MAX_NODES] + 1))
    ):
        cg.add(var.allow_node(node_id))
    for peer in config.get(CONF_PEERS, []):
        if automatic:
            cg.add(
                var.add_auto_peer_restriction(
                    peer.get(CONF_NODE_ID, 0), peer[CONF_MAC_ADDRESS].parts
                )
            )
        else:
            cg.add(
                var.add_peer(
                    peer[CONF_NODE_ID],
                    peer[CONF_MAC_ADDRESS].parts,
                    list(bytes.fromhex(peer[CONF_LMK])),
                )
            )
