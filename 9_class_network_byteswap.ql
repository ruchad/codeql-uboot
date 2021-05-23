import cpp

class NetworkByteSwap extends Expr {
    NetworkByteSwap(){
        exists(MacroInvocation mi | mi.getMacroName().regexpMatch("ntoh(s|l|ll)") | this = mi.getExpr())
    }
}

from NetworkByteSwap n
select n, "Network Byte Swap"