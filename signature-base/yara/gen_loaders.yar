/*
   Yara Rule Set
   Copyright: Florian Roth
   Date: 2017-06-25
   Identifier: Rules that detect different malware characteristics
   Reference: Internal Research
   License: GPL
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule ReflectiveLoader {
   meta:
      description = "Detects a unspecified hack tool, crack or malware using a reflective loader - no hard match - further investigation recommended"
      reference = "Internal Research"
      score = 70
      date = "2017-07-17"
      modified = "2021-03-15"
      author = "Florian Roth"
      nodeepdive = 1
   strings:
      $x1 = "ReflectiveLoader" fullword ascii
      $x2 = "ReflectivLoader.dll" fullword ascii
      $x3 = "?ReflectiveLoader@@" ascii
      $x4 = "reflective_dll.x64.dll" fullword ascii
      $x5 = "reflective_dll.dll" fullword ascii

      $fp1 = "Sentinel Labs, Inc." wide
      $fp2 = "Panda Security, S.L." wide ascii
   condition:
      uint16(0) == 0x5a4d and (
            1 of ($x*) or
            pe.exports("ReflectiveLoader") or
            pe.exports("_ReflectiveLoader@4") or
            pe.exports("?ReflectiveLoader@@YGKPAX@Z")
         )
      and not 1 of ($fp*)
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-08-20
   Identifier: Reflective DLL Loader
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */

rule DLL_Injector_Lynx {
   meta:
      description = "Detects Lynx DLL Injector"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-08-20"
      hash1 = "d594f60e766e0c3261a599b385e3f686b159a992d19fa624fad8761776efa4f0"
   strings:
      $x1 = " -p <TARGET PROCESS NAME> | -u <DLL PAYLOAD> [--obfuscate]" fullword wide
      $x2 = "You've selected to inject into process: %s" fullword wide
      $x3 = "Lynx DLL Injector" fullword wide
      $x4 = "Reflective DLL Injector" fullword wide
      $x5 = "Failed write payload: %lu" fullword wide
      $x6 = "Failed to start payload: %lu" fullword wide
      $x7 = "Injecting payload..." fullword wide
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 800KB and
        1 of them
      ) or ( 3 of them )
}

rule Reflective_DLL_Loader_Aug17_4 {
   meta:
      description = "Detects Reflective DLL Loader"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-08-20"
      hash1 = "205b881701d3026d7e296570533e5380e7aaccaa343d71b6fcc60802528bdb74"
      hash2 = "f76151646a0b94024761812cde1097ae2c6d455c28356a3db1f7905d3d9d6718"
   strings:
      $x1 = "<H1>&nbsp;>> >> >> Keylogger Installed - %s %s << << <<</H1>" fullword ascii

      $s1 = "<H3> ----- Running Process ----- </H3>" fullword ascii
      $s2 = "<H2>Operating system: %s<H2>" fullword ascii
      $s3 = "<H2>System32 dir:  %s</H2>" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 2000KB and 2 of them
      )
}
