package gpu

const (
	// InstallationHostDir is the directory where gpu drivers will be installed on the host machine.
	InstallationHostDir = "/var/lib/nvidia"
	// InstallationContainerDir is the directory where gpu drivers will be available on the workload container.
	InstallationContainerDir = "/usr/local/nvidia"
	// GpuInstallerImageRefFilepath is a filename which has the container image reference of cos_gpu_installer.
	GpuInstallerImageRefFilepath = "/usr/share/oem/confidential_space/cos_gpu_installer_image_reference"
)
