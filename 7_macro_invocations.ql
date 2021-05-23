import cpp

// from MacroInvocation mi
// where
//     mi.getMacro().getName() in ["ntohs", "ntohl", "ntohll"]
// select 
//     mi, "Macro invocations"

 
from MacroInvocation mi
where
    mi.getMacro().getName().regexpMatch("ntoh(s|l|ll)")
select 
    mi