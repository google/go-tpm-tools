package gpu

const (
	// InstallationHostDir is the directory where gpu drivers will be installed on the host machine.
	InstallationHostDir = "/var/lib/nvidia"
	// InstallationContainerDir is the directory where gpu drivers will be available on the workload container.
	InstallationContainerDir = "/usr/local/nvidia"
	// HostRootPath is the path to root directory of the host
	HostRootPath = "/root"
)
