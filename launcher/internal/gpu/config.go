package gpu

const (
	// InstallationHostDir is the directory where gpu drivers will be installed on the host machine.
	InstallationHostDir = "/var/lib/nvidia"
	// BuiltInInstallation590_48_01HostDir host directory
	BuiltInInstallation590_48_01HostDir = "/opt/nvidia/590.48.01"
	// InstallationContainerDir is the directory where gpu drivers will be available on the workload container.
	InstallationContainerDir = "/usr/local/nvidia"
	// InstallerImageRef is the hardcoded image reference for cos_gpu_installer
	InstallerImageRef = "us.gcr.io/cos-cloud/cos-gpu-installer:v2.5.10"
	// InstallerDigest is the expected digest for cos_gpu_installer:v2.5.10
	InstallerDigest = "sha256:31f36d9ba262d7181c624fdeaab4b2148d6e0f8101671e583efe153792116b8d"
	// NvDriverVer590_48_01 is the version string for the driver
	NvDriverVer590_48_01 = "590.48.01"
	// NvDriverVer595_58_03 is the version string for the driver
	NvDriverVer595_58_03 = "595.58.03"
	// NvDriverVer595_58_03Digest is driver run file digest downloaded from
	// cos-nvidia-gpu-drivers/sha256/NVIDIA-Linux-x86_64-595.58.03.run.sha256
	NvDriverVer595_58_03Digest = "8c0d4f967b7932c4ab5714272aee8103392b0a702c92afa555176d36205829f9"
	// NvDriverVer595_58_03Runfile is the driver run file name
	NvDriverVer595_58_03Runfile = "NVIDIA-Linux-x86_64-595.58.03.run"
)
