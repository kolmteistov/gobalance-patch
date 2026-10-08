package param

const (
	// InitialCallbackDelay How long to wait for onionbalance to bootstrap before starting periodic
	// events (in seconds)
	InitialCallbackDelay = 45

	// FetchDescriptorFrequency Every how often we should be fetching instance descriptors (in seconds)
	FetchDescriptorFrequency = 10 * 60

	// PublishDescriptorCheckFrequency Every how often we should be checking whether we should publish our frontend
	// descriptor (in seconds). Triggering this callback doesn't mean we will
	// actually upload a descriptor. We only upload a descriptor if it has expired,
	// the intro points have changed, etc.
	PublishDescriptorCheckFrequency = 5 * 60

	// FrontendDescriptorLifetime How long should we keep a frontend descriptor before we expire it (in
	// seconds)?
	FrontendDescriptorLifetime        = 60 * 60
	FrontendDescriptorLifetimeTestnet = 20

	// NIntrosPerInstance How many intros should we use from each instance in the final frontend
	// descriptor?
	// [TODO: This makes no attempt to hide the use of onionbalance. In the future we
	// should be smarter and sneakier here.]
	NIntrosPerInstance = 2

	// InstanceDescriptorTooOld If we last received a descriptor for this instance more than
	// INSTANCE_DESCRIPTOR_TOO_OLD seconds ago, consider the instance to be down.
	InstanceDescriptorTooOld = 60 * 60

	// HsdirNReplicas Number of replicas per descriptor
	HsdirNReplicas = 2

	// HsdirSpreadStore How many uploads per replica
	// [TODO: Get these from the consensus instead of hardcoded]
	HsdirSpreadStore = 4

	// MaxDescriptorSize Max descriptor size (in bytes) (see hs_cache_get_max_descriptor_size() in
	// little-t-tor)
	MaxDescriptorSize = 50000
)
