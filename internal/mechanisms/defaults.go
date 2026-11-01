package mechanisms

// DefaultProxyPort is the loopback port proxied mechanisms use while being
// probed, and the port written into a standalone emitted profile. Emitted
// runner scripts do not depend on it: they choose a free port per run.
const DefaultProxyPort = 8899
