package gpu

const (
	// InstallationHostDir is the directory where gpu drivers will be installed on the host machine.
	InstallationHostDir = "/var/lib/nvidia"
	// InstallationContainerDir is the directory where gpu drivers will be available on the workload container.
	InstallationContainerDir = "/usr/local/nvidia"
	// InstallerImageRefFile is a filename which has the container image reference of cos_gpu_installer.
	InstallerImageRefFile = "/usr/share/oem/confidential_space/gpu/cos_gpu_installer_image_ref"
	// InstallerImageDigestFile is a filename which has the container image digest of cos_gpu_installer.
	InstallerImageDigestFile = "/usr/share/oem/confidential_space/gpu/cos_gpu_installer_image_digest"
	// ReferenceDriverDigestFile is a filename which has the reference digest of nvidia driver installer.
	ReferenceDriverDigestFile = "/usr/share/oem/confidential_space/gpu/driver_digest_sha256sum"
)
