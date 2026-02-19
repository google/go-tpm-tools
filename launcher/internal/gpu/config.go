package gpu

const (
	// InstallationHostDir is the directory where gpu drivers will be installed on the host machine.
	InstallationHostDir = "/var/lib/nvidia"
	// InstallationContainerDir is the directory where gpu drivers will be available on the workload container.
	InstallationContainerDir = "/usr/local/nvidia"
	// InstallerImageRef is the hardcoded image reference for cos_gpu_installer
	InstallerImageRef = "us.gcr.io/cos-cloud/cos-gpu-installer:v2.5.10"
	// InstallerDigest is the expected digest for cos_gpu_installer:v2.5.10
	InstallerDigest = "sha256:31f36d9ba262d7181c624fdeaab4b2148d6e0f8101671e583efe153792116b8d"
	// NvDriverVer590_48_01 is the version string for the driver
	NvDriverVer590_48_01 = "590.48.01"
	// NvDriverVer590_48_01Digest is driver run file digest downloaded from
	// cos-nvidia-gpu-drivers/sha256/NVIDIA-Linux-x86_64-590.48.01.run.sha256
	NvDriverVer590_48_01Digest = "b9e2f80693781431cc87f4cd29109e133dcecb50a50d6b68d4b3bf2d696bd689"
	// NvDriverVer590_48_01Runfile is the driver run file name
	NvDriverVer590_48_01Runfile = "NVIDIA-Linux-x86_64-590.48.01.run"
)
