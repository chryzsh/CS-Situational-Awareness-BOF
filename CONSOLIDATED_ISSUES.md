# Consolidated BOF Issues

**Sources**: CODE_REVIEW_FINDINGS.md + bof_review_checklist.md
**Total BOFs**: 61

Criticality key:
- **CRITICAL** - Security vulnerabilities, crashes, memory corruption
- **HIGH** - Significant bugs, unsafe patterns, missing validation
- **MEDIUM** - Code quality, magic numbers, const correctness, documentation
- **LOW** - Typos, commented-out code, style

Status key:
- (blank) - Not yet reviewed
- **FIXED** - Issue resolved
- **FP** - False positive, not actually an issue
- **WONTFIX** - Acknowledged but not worth fixing

---

## adcs_enum
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | CRITICAL | Copy-paste error in CHECK_RETURN_FALSE message - says "CertGetCertificateChain()" but actually calls GetSecurityDescriptorOwner | adcs_enum.c:824 | |
| 2 | MEDIUM | Missing function documentation | adcs_enum.c:157, 212, 328, 431, 621, 804 | |
| 3 | MEDIUM | Const correctness - parameter `domain` should be const | adcs_enum.c:157 | |
| 4 | MEDIUM | Complex ACL parsing logic lacks comments | adcs_enum.c:473-607 | |

---

## adcs_enum_com
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | MEDIUM | Missing function documentation | entry.c:13; adcs_enum_com.c:193, 216, 299, 354, 471, 517, 589, 715, 782 | |
| 2 | MEDIUM | Unused variables: pwszServer, pwszNameSpace, pwszQuery | entry.c:20-22 | |
| 3 | MEDIUM | Const correctness: Multiple BSTR parameters should be const | entry.c | |
| 4 | MEDIUM | Magic numbers: 1, 31536000, 86400 (seconds-per-year/day) | adcs_enum_com.c:373, 627, 633 | |
| 5 | LOW | Typo: "retrive" should be "retrieve" | adcs_enum_com.c:271 | |
| 6 | LOW | Wrong comment: "Template Validity Period" should be "Template Renewal Period" | adcs_enum_com.c:633 | |
| 7 | LOW | Multiple commented debug statements | adcs_enum_com.c | |

---

## adcs_enum_com2
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | MEDIUM | Missing function documentation | entry.c:11; adcs_enum_com2.c:180, 201, 249, 283, 365, 434, 564, 626, 835, 867, 977, 1045 | |
| 2 | MEDIUM | Unused variables: pwszServer, pwszNameSpace, pwszQuery | entry.c:18-20 | |
| 3 | MEDIUM | Const correctness: All BSTR parameters should be const | entry.c | |
| 4 | MEDIUM | Magic numbers: 1, 31536000, 86400 | adcs_enum_com2.c:461, 891, 897 | |
| 5 | LOW | Duplicate printf of Flags field | adcs_enum_com2.c:720-725 | |
| 6 | LOW | Multiple commented debug statements | adcs_enum_com2.c | |

---

## adv_audit_policies
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | CRITICAL | Stack overflow vulnerability from unbounded recursion | entry.c | |
| 2 | CRITICAL | Memory leaks in policy enumeration paths | entry.c | |
| 3 | HIGH | Recursion depth should be limited to prevent stack exhaustion | entry.c | |
| 4 | HIGH | Resource cleanup incomplete in error paths | entry.c | |
| 5 | HIGH | No input validation for iswow64 parameter | entry.c:323 | |
| 6 | MEDIUM | Missing function documentation | entry.c:10, 128, 303 | |
| 7 | MEDIUM | Const correctness: swzFileName should be const | entry.c:10 | |
| 8 | MEDIUM | Complex CSV parsing logic lacks detailed comments | entry.c:218-228 | |
| 9 | LOW | Comment formatting: extra tabs | entry.c:54 | |

---

## arp
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | MEDIUM | Missing function documentation | entry.c:9, 23, 36, 58, 112 | |
| 2 | MEDIUM | Const correctness: `physaddr` and return type should be const | entry.c:23, 36 | |
| 3 | LOW | Typo: "Inteface" should be "Interface" | entry.c:86 | |
| 4 | LOW | Inconsistent naming: Mixed snake_case conventions | entry.c | |

---

## cacls
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | MEDIUM | Missing function documentation | entry.c:27, 58, 66, 356, 365, 408, 488 | |
| 2 | MEDIUM | Magic number: Uses 0xFFFFFFFF instead of INVALID_FILE_ATTRIBUTES | entry.c:394 | |
| 3 | MEDIUM | Non-descriptive function names: LovingIt(), DoneLovingIt() | entry.c:27, 58 | |
| 4 | MEDIUM | Const correctness: Multiple parameters could be const | entry.c | |
| 5 | MEDIUM | Large stack arrays (MAX_PATH buffers) | entry.c | |
| 6 | LOW | Commented out code | entry.c:237, 243, 250, 311 | |

---

## dir
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | CRITICAL | Modifies input buffer unsafely - could corrupt caller data | entry.c | |
| 2 | CRITICAL | Unbounded recursion in directory traversal | entry.c | |
| 3 | HIGH | Recursion depth should be limited for deeply nested directories | entry.c | |
| 4 | MEDIUM | Missing function documentation | entry.c:6, 112 | |
| 5 | MEDIUM | Const correctness: subdirs parameter could be const | entry.c:6 | |
| 6 | MEDIUM | UNC path handling comment could be clearer | entry.c:20-22 | |
| 7 | MEDIUM | Magic buffer size 1024 | entry.c:124 | |
| 8 | LOW | Typo: "ujust" should be "just" | entry.c:63 | |

---

## driversigs
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | MEDIUM | Missing function documentation | entry.c:10, 30, 39, 200, 344 | |
| 2 | MEDIUM | Const correctness: file_path should be const | entry.c:39 | |
| 3 | MEDIUM | Hardcoded driver vendor list | entry.c:56-63 | |
| 4 | MEDIUM | Missing documentation for IMAGEHLP$ functions | entry.c:109, 127, 143 | |
| 5 | MEDIUM | Large stack arrays present | entry.c | |
| 6 | LOW | Commented out code with explanation | entry.c:64 | |
| 7 | LOW | Typo: "IMagePath" should be "ImagePath" | entry.c:288 | |

---

## enum_filter_driver
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | MEDIUM | Missing function documentation | entry.c:11, 182 | |
| 2 | MEDIUM | Const correctness: szHostName should be const | entry.c:11 | |
| 3 | MEDIUM | Magic numbers for filter altitudes without explanation | entry.c:97, 101, 105 | |
| 4 | MEDIUM | Complex nested loop logic lacks high-level comments | entry.c:57-153 | |
| 5 | LOW | Many commented debug printf statements | entry.c:62, 68, 74, 81, 87, 95 | |

---

## enumLocalSessions
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | HIGH | NetApiBufferFree called on potentially NULL pointer | entry.c | |
| 2 | MEDIUM | Missing function documentation | entry.c:7, 91 | |
| 3 | MEDIUM | Inconsistent error message formatting | entry.c:69, 80 | |
| 4 | MEDIUM | Variable naming 'freedomain' and 'freestation' unclear | entry.c:31-33 | |
| 5 | MEDIUM | Magic state values WTSActive, WTSDisconnected used without comment | entry.c:46 | |

---

## env
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | HIGH | go() function has wrong signature - missing Buffer/Length parameters | entry.c:37 | |
| 2 | MEDIUM | Missing function documentation | entry.c:7, 37 | |
| 3 | MEDIUM | No error handling for lstrlenA failure | entry.c:30 | |

---

## findLoadedModule
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | MEDIUM | Missing function documentation | entry.c:6, 31, 77 | |
| 2 | MEDIUM | Const correctness: modSearchString and procSearchString should be const | entry.c:6, 31 | |
| 3 | MEDIUM | No validation that PID is valid before snapshot | entry.c:12 | |
| 4 | MEDIUM | Inconsistent return value usage | entry.c:20-21 | |
| 5 | MEDIUM | Large stack arrays for module paths | entry.c | |
| 6 | LOW | Commented debug printf | entry.c:46 | |
| 7 | LOW | Comment suggests uncertainty about design | entry.c:18 | |

---

## get_password_policy
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | HIGH | NetApiBufferFree on potentially NULL pointer | entry.c | |
| 2 | MEDIUM | Missing function documentation | entry.c:6, 74 | |
| 3 | MEDIUM | Const correctness: serverName should be const | entry.c:6 | |
| 4 | MEDIUM | Magic numbers for time conversions: 86400, 60, 1000 | entry.c:22-24, 46-47 | |
| 5 | MEDIUM | Duplicate error message | entry.c:30, 54 | |
| 6 | MEDIUM | Reusing strresult buffer without clearing | entry.c:11 | |
| 7 | MEDIUM | Inconsistent formatting of internal_printf | entry.c:20-25, 46-49 | |
| 8 | LOW | Informal comment "#thanksMSDN" | entry.c:12 | |

---

## get_session_info
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | MEDIUM | Missing function documentation | entry.c:8, 35, 60, 119 | |
| 2 | LOW | Commented out debug print | entry.c:18 | |

---

## ipconfig
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | CRITICAL | Stack allocation exceeds 4KB - should be heap-allocated | entry.c:11 | |
| 2 | MEDIUM | Missing function documentation | entry.c:10, 91 | |
| 3 | MEDIUM | Magic number: sizeof(IP_ADAPTER_INFO) * 32 | entry.c:11, 16 | |
| 4 | MEDIUM | Repetitive identical error messages make debugging difficult | entry.c:23, 31, 36, 43 | |

---

## ldapsearch
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | CRITICAL | malloc without NULL checks | entry.c:99-100 | |
| 2 | CRITICAL | malloc without NULL checks | entry.c:313 | |
| 3 | HIGH | Memory leaks possible in error paths | entry.c | |
| 4 | HIGH | Inconsistent dynamic resolution: Uses LoadLibraryA/GetProcAddress directly | entry.c:298-300, 368-371 | |
| 5 | MEDIUM | Missing function documentation | entry.c:69, 76, 113, 144, 202, 292, 334, 346, 553 | |
| 6 | MEDIUM | Unusual initialization: Function pointers to `(void *)1` with comment about function slot limits | entry.c:21-23 | |
| 7 | MEDIUM | Magic numbers: 1024 buffer, 20 second timeout, page size 64 | entry.c:347, 360, 416 | |
| 8 | MEDIUM | Const correctness: Multiple parameters could be const | entry.c | |
| 9 | MEDIUM | Complex paging loop lacks strategy comment | entry.c:414-511 | |
| 10 | MEDIUM | Long conditional statements difficult to read | entry.c:309, 468-469 | |

---

## listdns
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | MEDIUM | Missing struct documentation | entry.c:6-12 | |
| 2 | MEDIUM | Missing function documentation | entry.c:14, 47 | |

---

## list_firewall_rules
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | MEDIUM | Missing struct documentation | entry.c:20-24 | |
| 2 | MEDIUM | Missing function documentation | entry.c:26, 229, 250, 358 | |
| 3 | MEDIUM | Magic number: hardcoded 3 in loop | entry.c:129 | |
| 4 | MEDIUM | Const correctness: DumpFWRulesInCollection parameter could be const | entry.c | |

---

## listmods
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | MEDIUM | Missing function documentation | entry.c:8, 53, 102 | |
| 2 | MEDIUM | Const correctness: szFile should be const | entry.c:8 | |
| 3 | MEDIUM | Magic numbers: buffer size 256 | entry.c:22-23 | |
| 4 | MEDIUM | TODO comment: "Add argument to exclude Microsoft DLLs" - incomplete feature | entry.c:101 | |
| 5 | MEDIUM | Large stack arrays for module paths | entry.c | |
| 6 | LOW | Commented out debug code | entry.c:79 | |
| 7 | LOW | Misleading "(debug)" comment | entry.c:61 | |

---

## listpipes
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | CRITICAL | BOF does not exist - implementation missing | N/A | |

---

## locale
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | MEDIUM | Missing function documentation | entry.c:6 | |
| 2 | MEDIUM | Magic number: BUFFER_SIZE 85 without explanation | entry.c:13 | |

---

## netGroupList (netgroup)
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | HIGH | NetApiBufferFree on potentially NULL pointer | entry.c | |
| 2 | MEDIUM | Missing function documentation | entry.c:8, 45, 77 | |
| 3 | MEDIUM | Operator precedence issue needs parentheses | entry.c:17 | |
| 4 | MEDIUM | Magic number: 100 for records per query | entry.c:16 | |
| 5 | MEDIUM | Type parameter logic lacks explanation | entry.c:111-117 | |

---

## netGroupListMembers
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | HIGH | NetApiBufferFree on potentially NULL pointer | entry.c | |
| 2 | MEDIUM | Missing function documentation | entry.c | |

---

## netLocalGroupList (netlocalgroup)
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | HIGH | NetApiBufferFree on potentially NULL pointer | entry.c | |
| 2 | HIGH | Potential NULL pointer issue after free | entry.c:30 | |
| 3 | MEDIUM | Missing function documentation | entry.c:8, 39, 71 | |
| 4 | MEDIUM | Naming typo: `ListserverGroups` should be `ListServerGroups` | entry.c:8 | |
| 5 | MEDIUM | Missing const correctness | entry.c | |
| 6 | MEDIUM | Type parameter logic lacks comments | entry.c:91-97 | |

---

## netLocalGroupListMembers
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | HIGH | NetApiBufferFree on potentially NULL pointer | entry.c | |
| 2 | MEDIUM | Missing function documentation | entry.c | |

---

## netlocalgroup2 (netLocalGroupListMembers2)
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | CRITICAL | Memory leak - sidstr from ConvertSidToStringSidW never freed with LocalFree | entry.c:23 | |
| 2 | HIGH | NetApiBufferFree on potentially NULL pointer | entry.c | |
| 3 | MEDIUM | Missing function documentation | entry.c:8, 79 | |
| 4 | MEDIUM | Missing error checking after ConvertSidToStringSidW | entry.c:23 | |
| 5 | MEDIUM | Missing const correctness | entry.c | |
| 6 | MEDIUM | Complex SID type checking could use switch/lookup | entry.c:44-63 | |
| 7 | MEDIUM | GetComputerNameExW return value not checked | entry.c:32 | |

---

## netloggedon
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | HIGH | NetApiBufferFree on potentially NULL pointer | entry.c | |
| 2 | MEDIUM | Missing function documentation | entry.c:6, 44 | |
| 3 | MEDIUM | Missing const correctness | entry.c | |
| 4 | LOW | Vague comment about "system allocated data" | entry.c:12 | |

---

## netloggedon2
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | HIGH | NetApiBufferFree on potentially NULL pointer | entry.c | |
| 2 | MEDIUM | Missing function documentation | entry.c:6, 56 | |
| 3 | MEDIUM | Missing const correctness | entry.c | |
| 4 | MEDIUM | Largely duplicates netloggedon | entry.c | |

---

## netsession (get-netsession)
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | HIGH | NetApiBufferFree on potentially NULL pointer | entry.c | |
| 2 | MEDIUM | Missing function documentation | entry.c:9, 97 | |
| 3 | MEDIUM | Duplicate include: windows.h appears twice | entry.c:1, 5 | |
| 4 | MEDIUM | Missing const correctness | entry.c | |
| 5 | LOW | Commented out pragma | entry.c:8 | |

---

## netsession2 (get-netsession2)
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | HIGH | Inconsistent API resolution: LoadLibraryA/GetProcAddress used directly | entry.c:80-90 | |
| 2 | HIGH | Inconsistent API resolution: FreeLibrary instead of KERNEL32$FreeLibrary | entry.c:261 | |
| 3 | HIGH | NetApiBufferFree on potentially NULL pointer | entry.c | |
| 4 | MEDIUM | Missing function documentation | entry.c:17, 49, 267 | |
| 5 | MEDIUM | Duplicate include: windows.h twice | entry.c:1, 5 | |
| 6 | MEDIUM | Missing const correctness | entry.c | |
| 7 | MEDIUM | Complex DNS resolution logic needs comments | entry.c:78-212 | |
| 8 | MEDIUM | Magic number: 260 | entry.c:121 | |
| 9 | LOW | Commented out code | entry.c:112-113 | |
| 10 | LOW | Unnecessary goto END | entry.c:252 | |
| 11 | LOW | Assumption comment indicates unclear logic | entry.c:98 | |

---

## netshares
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | HIGH | NetApiBufferFree on potentially NULL pointer | entry.c | |
| 2 | MEDIUM | Missing function documentation | entry.c:6, 38, 71 | |
| 3 | MEDIUM | Missing const correctness | entry.c | |
| 4 | LOW | Variable naming inconsistency | entry.c:80 | |

---

## netstat
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | CRITICAL | Pointer assignment bug in GetNameByPID() - incorrect pointer parameter assignments | entry.c:72-73, 77-78 | |
| 2 | CRITICAL | Debug code left in: `if (1 \|\|...)` makes condition always true | entry.c:166 | |
| 3 | CRITICAL | Global static array usage - makes BOF non-reentrant | entry.c:23-37 | |
| 4 | HIGH | TCP/UDP table iteration logic has bugs | entry.c | |
| 5 | MEDIUM | Missing function documentation for all helper functions | entry.c | |
| 6 | MEDIUM | Manual function declarations instead of headers | entry.c:15-17 | |
| 7 | MEDIUM | Inefficient manual array zeroing | entry.c:120-121, 187-188 | |
| 8 | MEDIUM | Missing const correctness | entry.c | |
| 9 | MEDIUM | Magic numbers for array sizes | entry.c | |
| 10 | LOW | Commented out code | entry.c:193 | |
| 11 | LOW | Header comment references ReactOS | entry.c:1-7 | |

---

## nettime
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | HIGH | NetApiBufferFree on potentially NULL pointer | entry.c | |
| 2 | MEDIUM | Missing function documentation | entry.c:7, 44 | |
| 3 | MEDIUM | Missing const correctness | entry.c | |
| 4 | MEDIUM | Uses MSVCRT$gmtime which returns static buffer | entry.c:24 | |
| 5 | LOW | Test/debug server name in main() | entry.c:74 | |

---

## netuptime
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | HIGH | NetApiBufferFree on potentially NULL pointer | entry.c | |
| 2 | MEDIUM | Missing function documentation | entry.c:6, 40 | |
| 3 | MEDIUM | Missing const correctness | entry.c | |
| 4 | MEDIUM | Unconventional memcpy use for LARGE_INTEGER | entry.c:24 | |
| 5 | MEDIUM | Missing NULL check on output | entry.c:21 | |
| 6 | LOW | Typo: "remotly" should be "remotely" | entry.c:32 | |

---

## netuser
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | HIGH | NetApiBufferFree on potentially NULL pointer | entry.c | |
| 2 | MEDIUM | Missing function documentation | entry.c:15, 32, 64, 232 | |
| 3 | MEDIUM | Magic numbers: TICKSTO1970, TICKSTO1980 need comments | entry.c:11-12 | |
| 4 | MEDIUM | Incomplete feature: "Not implemented" hardcoded | entry.c:146 | |
| 5 | MEDIUM | Missing const correctness | entry.c | |
| 6 | MEDIUM | NetUserGetLocalGroups uses NULL server | entry.c:178-179 | |
| 7 | MEDIUM | Complex flag checking needs comments | entry.c:92-159 | |
| 8 | LOW | x86 limitation message could be more helpful | entry.c:129 | |

---

## netuse (add/delete/list)
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | HIGH | NetApiBufferFree on potentially NULL pointer (netuse_list) | entry.c | |
| 2 | MEDIUM | Missing function documentation | entry.c | |
| 3 | MEDIUM | Magic numbers: 16384, 32768 | entry.c | |
| 4 | MEDIUM | Buffer size inconsistencies | entry.c:202 | |
| 5 | MEDIUM | Missing const correctness | entry.c | |
| 6 | MEDIUM | Inconsistent error handling approaches | entry.c | |
| 7 | MEDIUM | Duplicate condition check | entry.c:294 | |
| 8 | LOW | Commented out code | entry.c:407 | |
| 9 | LOW | Dead code: end: label | entry.c:409 | |

---

## netview
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | HIGH | NetApiBufferFree on potentially NULL pointer | entry.c | |
| 2 | MEDIUM | Missing function documentation | entry.c:9, 59 | |
| 3 | MEDIUM | Const correctness: domain should be const | entry.c:9 | |

---

## nslookup
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | CRITICAL | LoadLibraryA not dynamically resolved | entry.c:24 | |
| 2 | CRITICAL | GetProcAddress not dynamically resolved | entry.c:34-35 | |
| 3 | CRITICAL | FreeLibrary not dynamically resolved | entry.c:194 | |
| 4 | MEDIUM | Missing function documentation | entry.c:14, 199 | |
| 5 | MEDIUM | Const correctness: Parameters should be const | entry.c:14 | |
| 6 | LOW | Commented out code | entry.c:58-59, 124 | |

---

## probe
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | MEDIUM | Missing function documentation | entry.c:5, 48 | |
| 2 | MEDIUM | Const correctness: host should be const | entry.c:5 | |
| 3 | MEDIUM | Magic number: 5 second timeout | entry.c:26 | |
| 4 | MEDIUM | Magic number: select() first parameter | entry.c:34 | |

---

## regsession
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | MEDIUM | Missing function documentation | entry.c:6, 100 | |
| 2 | MEDIUM | Const correctness: Parameter should be const | entry.c:6 | |
| 3 | MEDIUM | Hardcoded SID prefix check using character comparisons | entry.c:51-57 | |
| 4 | MEDIUM | Magic number: 256 for buffer sizes | entry.c:13, 45-46 | |

---

## reg_query
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | MEDIUM | Missing function documentation for all functions | entry.c | |
| 2 | MEDIUM | Multiple parameters should be const | entry.c | |
| 3 | MEDIUM | Global variables with workaround initialization | entry.c:10-11 | |
| 4 | MEDIUM | Magic numbers for HKEY comparison | entry.c:30-46 | |
| 5 | MEDIUM | Magic number: 0x80000000 for HKEY base | entry.c:389 | |
| 6 | MEDIUM | Complex stack-based enumeration lacks comments | entry.c:258-362 | |
| 7 | MEDIUM | Large stack arrays for registry data | entry.c | |
| 8 | LOW | Commented out code | entry.c:62 | |

---

## reg_query_recursive
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | HIGH | Recursion depth should be limited | entry.c | |
| 2 | MEDIUM | Missing function documentation | entry.c | |

---

## resources
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | CRITICAL | Missing #ifdef BOF wrapper - may not compile correctly as BOF | entry.c:36 | |
| 2 | MEDIUM | Missing function documentation | entry.c:7, 36 | |
| 3 | MEDIUM | DIV constant (1048576) needs comment for MB conversion | entry.c:5 | |

---

## routeprint
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | MEDIUM | Missing function documentation | entry.c:15, 116 | |
| 2 | MEDIUM | Magic number: IPBUF = 17 | entry.c:12 | |
| 3 | MEDIUM | Magic number: DefGate buffer size 16 | entry.c:22 | |
| 4 | MEDIUM | FIXME comment for sorting not addressed | entry.c:60 | |
| 5 | MEDIUM | goto used for error handling | entry.c:107 | |
| 6 | LOW | Commented out attribution header | entry.c:1-7 | |

---

## sc_enum
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | CRITICAL | NULL dereference risks | entry.c:342-349 | |
| 2 | CRITICAL | Array bounds issues | entry.c:380 | |
| 3 | CRITICAL | Global variable pragmas - makes BOF non-reentrant | entry.c:8-14 | |
| 4 | HIGH | Service enumeration has unsafe array access | entry.c | |
| 5 | MEDIUM | Missing function documentation for multiple functions | entry.c | |
| 6 | MEDIUM | Multiple parameters should be const | entry.c | |
| 7 | MEDIUM | Magic number: SC_GROUP_IDENTIFIERA | entry.c:62 | |
| 8 | MEDIUM | Hardcoded service type values | entry.c:80-94 | |
| 9 | MEDIUM | Hardcoded action codes | entry.c:98-104 | |
| 10 | MEDIUM | Pragma warnings suppressed for pointer conversions | entry.c:6-14, 46-54, 401-404 | |
| 11 | MEDIUM | Complex enumeration logic needs comments | entry.c:324-400 | |

---

## sc_qc
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | CRITICAL | Array bounds issues | entry.c:11 | |
| 2 | CRITICAL | Global gServiceName variable - makes BOF non-reentrant | entry.c:131-132 | |
| 3 | HIGH | Buffer overflow potential in service config parsing | entry.c | |
| 4 | MEDIUM | Missing function documentation | entry.c | |
| 5 | MEDIUM | Multiple parameters should be const | entry.c | |
| 6 | MEDIUM | Hardcoded service type values | entry.c:21-37 | |
| 7 | MEDIUM | Magic number: SC_GROUP_IDENTIFIERA | entry.c:76 | |
| 8 | LOW | Commented out alternative output | entry.c:140 | |

---

## sc_qdescription
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | CRITICAL | NULL checks missing | entry.c:28 | |
| 2 | CRITICAL | NULL checks missing | entry.c:34 | |
| 3 | HIGH | Service handle operations lack validation | entry.c | |
| 4 | HIGH | Description buffer could be NULL dereferenced | entry.c | |
| 5 | MEDIUM | Missing function documentation | entry.c:5, 59 | |
| 6 | MEDIUM | Parameters should be const | entry.c:5 | |

---

## sc_qfailure
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | CRITICAL | NULL checks missing | entry.c:8 | |
| 2 | CRITICAL | NULL checks missing | entry.c:35 | |
| 3 | CRITICAL | Unsafe array access | entry.c:58 | |
| 4 | HIGH | Service failure action array not validated | entry.c | |
| 5 | HIGH | Buffer allocations not checked | entry.c | |
| 6 | MEDIUM | Missing function documentation | entry.c | |
| 7 | MEDIUM | Parameters should be const | entry.c | |
| 8 | MEDIUM | Global variable gServiceName | entry.c:8 | |
| 9 | MEDIUM | Hardcoded action codes | entry.c:10-17 | |

---

## sc_qtriggerinfo
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | CRITICAL | NULL checks missing | entry.c:64 | |
| 2 | CRITICAL | Array bounds issues | entry.c:86 | |
| 3 | CRITICAL | Array bounds issues | entry.c:88 | |
| 4 | HIGH | Trigger data array access unsafe | entry.c | |
| 5 | HIGH | Data structure pointers not validated | entry.c | |
| 6 | MEDIUM | Missing function documentation | entry.c | |
| 7 | MEDIUM | Parameters should be const | entry.c | |
| 8 | MEDIUM | Global variables with workaround initialization | entry.c:8-11 | |
| 9 | MEDIUM | Magic number: SERVICE_CONFIG_TRIGGER_INFO = 8 | entry.c:13 | |
| 10 | MEDIUM | Hardcoded trigger type values | entry.c:37-39 | |
| 11 | MEDIUM | MinGW-specific typedef workarounds | entry.c:15-33 | |
| 12 | MEDIUM | Magic numbers for trigger type checks | entry.c:91-92 | |

---

## sc_query
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | CRITICAL | Array bounds issues | entry.c:104 | |
| 2 | CRITICAL | NULL checks missing | entry.c:141-142 | |
| 3 | HIGH | Service enumeration buffer not validated | entry.c | |
| 4 | HIGH | Status buffer could overflow | entry.c | |
| 5 | MEDIUM | Missing function documentation | entry.c | |
| 6 | MEDIUM | Parameters should be const | entry.c | |
| 7 | MEDIUM | Global variables | entry.c:8-9 | |
| 8 | MEDIUM | Hardcoded service type values | entry.c:17-34 | |

---

## schtasksenum
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | CRITICAL | NULL checks missing | entry.c:24 | |
| 2 | CRITICAL | NULL checks missing | entry.c:26 | |
| 3 | CRITICAL | Array bounds issues | entry.c:142 | |
| 4 | HIGH | Task folder enumeration lacks validation | entry.c | |
| 5 | HIGH | COM object pointers used without checks | entry.c | |
| 6 | MEDIUM | Missing function documentation | entry.c:14, 199 | |
| 7 | MEDIUM | Parameter should be const | entry.c:14 | |
| 8 | MEDIUM | Hardcoded GUIDs/IIDs | entry.c:43-44 | |
| 9 | MEDIUM | Magic numbers for task enumeration flags | entry.c:85, 101 | |
| 10 | MEDIUM | Complex COM/Task Scheduler logic needs comments | entry.c:83-178 | |
| 11 | LOW | Commented out code | entry.c:8 | |

---

## schtasksquery
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | CRITICAL | NULL checks missing | entry.c:24 | |
| 2 | CRITICAL | NULL checks missing | entry.c:26 | |
| 3 | CRITICAL | Array bounds issues | entry.c:102 | |
| 4 | HIGH | Task query lacks proper validation | entry.c | |
| 5 | HIGH | COM object pointers used without checks | entry.c | |
| 6 | MEDIUM | Missing function documentation | entry.c:14, 156 | |
| 7 | MEDIUM | Parameters should be const | entry.c | |
| 8 | MEDIUM | Hardcoded GUIDs/IIDs | entry.c:38-39 | |
| 9 | LOW | Commented out code | entry.c:8, 63 | |
| 10 | LOW | Duplicate variable declaration commented out | entry.c:63 | |

---

## tasklist
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | CRITICAL | Array bounds checking issues | entry.c:68-73 | |
| 2 | HIGH | WMI result iteration could access beyond bounds | entry.c | |
| 3 | MEDIUM | Missing function documentation | entry.c:18, 100 | |
| 4 | MEDIUM | Parameter should be const | entry.c:19 | |
| 5 | MEDIUM | Magic numbers for column indices | entry.c:12-16 | |
| 6 | MEDIUM | Unused variable ullQuerySize | entry.c:24 | |
| 7 | LOW | Typo: "resuls" should be "results" | entry.c:64 | |

---

## uptime
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | MEDIUM | Missing function documentation | entry.c:7, 38, 51 | |
| 2 | MEDIUM | Magic number: 10000 for tick conversion | entry.c:29 | |
| 3 | MEDIUM | Hardcoded divisors for time conversion | entry.c:11-14, 42-45 | |

---

## useridletime
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | MEDIUM | Missing function documentation | entry.c:5, 31 | |
| 2 | MEDIUM | Magic numbers for time conversions | entry.c:14-18 | |
| 3 | MEDIUM | Pragma comment directive ineffective in BOF | entry.c:27 | |
| 4 | LOW | Commented out code | entry.c:21 | |

---

## vssenum
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | CRITICAL | NULL checks missing | entry.c:39 | |
| 2 | CRITICAL | Buffer overrun risk | entry.c:68 | |
| 3 | CRITICAL | NULL checks missing | entry.c:96 | |
| 4 | HIGH | VSS enumeration lacks validation | entry.c | |
| 5 | HIGH | COM object operations unsafe | entry.c | |
| 6 | MEDIUM | Missing function documentation | entry.c:7, 114 | |
| 7 | MEDIUM | Parameters should be const | entry.c | |
| 8 | MEDIUM | Magic number: FSCTL_SRV_ENUMERATE_SNAPSHOTS = 0x00144064 | entry.c:5 | |
| 9 | MEDIUM | Magic number: Initial buffer size 16 | entry.c:38 | |
| 10 | MEDIUM | Hardcoded offsets for structure parsing | entry.c:63-65, 91-92 | |
| 11 | MEDIUM | Complex snapshot enumeration needs comments | entry.c:46-97 | |

---

## whoami
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | CRITICAL | Multiple NULL checks missing | entry.c:87 | FP - NULL checked at line 93 |
| 2 | CRITICAL | NULL checks missing | entry.c:136 | FP - NULL checked at line 139 |
| 3 | CRITICAL | NULL checks missing | entry.c:235 | FP - NULL checked at line 239 |
| 4 | CRITICAL | Buffer overflow risks | entry.c:128-132 | FP - LookupAccountSidA respects size params, max 255 |
| 5 | CRITICAL | Buffer overflow risks | entry.c:178 | FP - sprintf into 1024 buf, max input ~511 bytes |
| 6 | HIGH | Token information retrieval lacks validation | entry.c | FIXED - goto cleanup pattern, ownership transfer |
| 7 | HIGH | SID conversion could fail without checks | entry.c | FIXED - check return value, match WhoamiGroups pattern |
| 8 | MEDIUM | Missing function documentation | entry.c:24, 41, 85, 123, 233, 309 | WONTFIX |
| 9 | MEDIUM | Some parameters should be const | entry.c | FP - no pointer params, all pass-by-value enums or void |
| 10 | MEDIUM | Magic numbers: MAX_PATH, 255, 0x60, 0x07 | entry.c:26, 128-129, 174-175 | WONTFIX |
| 11 | MEDIUM | Complex SID/privilege enumeration needs comments | entry.c | WONTFIX - already has adequate step comments |
| 12 | LOW | Commented out printf statements | entry.c:60, 71 | FIXED |

---

## windowlist
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | MEDIUM | Missing function documentation | entry.c:9, 31 | |
| 2 | MEDIUM | Global variable ALL instead of lParam passing | entry.c:6 | |
| 3 | MEDIUM | Global variable JUNK as workaround for relocation | entry.c:7 | |
| 4 | MEDIUM | Magic numbers: 128 and 127 for buffer sizes | entry.c:10-11 | |
| 5 | MEDIUM | Unused iphlpapi.h include | entry.c:2 | |

---

## wmi_query
| # | Criticality | Description | Location | Status |
|---|-------------|-------------|----------|--------|
| 1 | CRITICAL | Array bounds checking issues | entry.c:58-71 | |
| 2 | HIGH | WMI result parsing could access beyond bounds | entry.c | |
| 3 | HIGH | COM variant handling needs validation | entry.c | |
| 4 | MEDIUM | Missing function documentation | entry.c:8, 99 | |
| 5 | MEDIUM | Multiple parameters should be const | entry.c | |
| 6 | MEDIUM | Unused variable ullColumnsSize | entry.c:17 | |
| 7 | MEDIUM | Unused parameters pwszServer and pwszNameSpace | entry.c:9-10 | |

---

## Summary Counts

| Criticality | Count |
|-------------|-------|
| CRITICAL | ~48 issues across 21 BOFs |
| HIGH | ~45 issues across 25+ BOFs |
| MEDIUM | ~180+ issues across all 61 BOFs |
| LOW | ~35 issues across ~20 BOFs |
