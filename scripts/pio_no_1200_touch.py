Import("env")

# Product install env: do NOT 1200bps-touch (device is Serial/JTAG, not product CDC reboot path)
env.BoardConfig().update("upload.use_1200bps_touch", False)
env.BoardConfig().update("upload.wait_for_upload_port", False)
