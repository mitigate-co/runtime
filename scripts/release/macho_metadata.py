"""Read only the minimum OS/CPU facts of our thin 64-bit macOS CLI artifacts.

This is not signature verification or a general Mach-O loader. Call only after
publisher authentication; native Apple verification is still mandatory.
"""

import struct

from install_contract import require

CPUS = {"aarch64-apple-darwin": 0x0100000C, "x86_64-apple-darwin": 0x01000007}


def minimum_system(data, target):
    require(target in CPUS and len(data) >= 32, "release_macho")
    magic, cpu, _, kind, count, size, _, reserved = struct.unpack_from("<8I", data)
    require(
        magic == 0xFEEDFACF
        and cpu == CPUS[target]
        and kind == 2
        and reserved == 0
        and 0 < count <= 1024
        and 0 < size <= 1024 * 1024
        and 32 + size <= len(data),
        "release_macho",
    )
    position, end, versions = 32, 32 + size, []
    for _ in range(count):
        require(position + 8 <= end, "release_macho")
        command, length = struct.unpack_from("<2I", data, position)
        require(
            length >= 8 and length % 8 == 0 and position + length <= end,
            "release_macho",
        )
        if command == 0x32:  # LC_BUILD_VERSION; the platform must be macOS.
            require(length >= 24, "release_macho")
            platform, version, _, tools = struct.unpack_from("<4I", data, position + 8)
            require(platform == 1 and length == 24 + tools * 8, "release_macho")
            versions.append(version)
        elif command == 0x24:  # LC_VERSION_MIN_MACOSX, used by older deployments.
            require(length == 16, "release_macho")
            versions.append(struct.unpack_from("<I", data, position + 8)[0])
        elif command in {0x25, 0x2F, 0x30}:  # iOS, tvOS and watchOS are not macOS.
            require(False, "release_macho")
        position += length
    require(position == end and len(versions) == 1, "release_macho")
    version = versions[0]
    minimum = (version >> 16, version >> 8 & 255, version & 255)
    require(10 <= minimum[0] <= 99, "release_macho")
    return minimum


def requirement(minimum):
    # Homebrew's runtime floor is Big Sur. Earlier artifact minima add no useful
    # restriction. Do not round a newer patch/minor minimum down to a major.
    if minimum <= (11, 0, 0):
        return "depends_on :macos"
    require(minimum[1:] == (0, 0), "homebrew_minimum_requires_review")
    return f'depends_on macos: ">= {minimum[0]}"'
