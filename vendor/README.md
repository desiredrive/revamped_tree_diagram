# RSA wheels go here

The launcher installs RSA (Cisco Remote Support Authorization, formerly RADKit)
from `vendor/<your-platform>/`. Drop the matching `cisco_radkit_*.whl` files
into the right subdirectory and the launcher will pick them up on next start.

| Platform               | Directory               | Wheel filenames                                |
|------------------------|-------------------------|------------------------------------------------|
| Linux x86_64           | `linux-x86_64/`         | `cisco_radkit_*-cp312-none-manylinux*_x86_64.whl` |
| macOS Apple Silicon    | `macos-arm64/`          | `cisco_radkit_*-cp312-none-macosx_*_arm64.whl`    |
| macOS Intel            | `macos-x86_64/`         | `cisco_radkit_*-cp312-none-macosx_*_x86_64.whl`   |
| Windows x86_64         | `windows-x86_64/`       | `cisco_radkit_*-cp312-none-win_amd64.whl`         |

Required four wheels per platform: `client`, `common`, `genie`, `service`.
Get them from https://radkit.cisco.com/docs/ and commit them to your fork —
the launcher's `git pull` will then deliver them to every TAC engineer.
