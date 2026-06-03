Drop the four RADKit 1.9.9 cp312 wheels for your OS into THIS folder,
then run the launcher.

Where to download them
======================

  https://radkit.cisco.com/downloads/release/

Pick **1.9.9** and grab the four wheels for your platform:

  cisco_radkit_client-1.9.9-cp312-...-<your-platform>.whl
  cisco_radkit_common-1.9.9-cp312-...-<your-platform>.whl
  cisco_radkit_genie-1.9.9-cp312-...-<your-platform>.whl
  cisco_radkit_service-1.9.9-cp312-...-<your-platform>.whl

Tag suffix by OS:
  macOS Apple Silicon  -> macosx_11_0_arm64
  macOS Intel          -> macosx_10_15_x86_64
  Windows 64-bit       -> win_amd64
  Linux 64-bit         -> manylinux1_x86_64  (already bundled — skip)

How it works
============

The launcher (run.sh / SDA-Pathfinder.command / SDA-Pathfinder.bat /
run.bat) installs every *.whl it finds in this folder into the project
virtualenv. pip picks the wheel matching your OS automatically; the
others are ignored.

You only need to do this once per machine. After install, you can leave
the wheels here or delete them.
