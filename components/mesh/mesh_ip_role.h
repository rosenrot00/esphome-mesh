#pragma once

#include "mesh_limits.h"

// Fixed ip_gateway builds and leaf nodes retain one immutable role. Dynamic
// ip_gateways candidates omit both flags so they can be gateway or client as
// native Wi-Fi changes. Standalone tests also use the complete runtime adapter.
#if defined(MESH_IP_CLIENT_ONLY) && defined(MESH_IP_GATEWAY_ONLY)
#error "A mesh IP build cannot be both gateway-only and client-only"
#endif
