import "pe"
import "math"

rule blackcat_found {
	meta:
		author = "Gabriel De Jesus"
		date = "05/10/2022"
		description = "BlackCat Ransomware detection via section metadata, entropy, and imports"
		version = "1.0"
	strings:
		$a = "uespemosarenegylmodnarodsetybdet"

	condition:
		pe.is_pe
		and pe.sections[3].name == ".eh_fram"
		and pe.sections[6].name == ".CRT"
		and pe.sections[7].name == ".tls"
		and pe.imports("netapi32.dll", "NetShareEnum")
		and pe.imports("bcrypt.dll", "BCryptGenRandom")
		and pe.imports("msvcrt.dll", "memcpy")
		and pe.imports("WS2_32.dll", "connect")
		and pe.imports("RstrtMgr.dll", "RmRegisterResources")
		and $a
		and math.entropy(pe.sections[2].raw_data_offset, pe.sections[2].raw_data_size) >= 6
		and math.entropy(pe.sections[6].raw_data_offset, pe.sections[6].raw_data_size) <= 0.7
}
